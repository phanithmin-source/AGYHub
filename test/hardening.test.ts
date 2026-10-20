import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { resolveExecutable } from '../src/util/exec.js';
import { withLock } from '../src/vault/lock.js';
import { Vault } from '../src/vault/vault.js';
import { deriveKek, subkey, sealJson } from '../src/vault/crypto.js';
import { addFromLive, switchTo, lockLive, type Ctx } from '../src/core/switchService.js';
import { requireProfile } from '../src/core/profiles.js';
import { exportProfiles, importProfiles } from '../src/core/transfer.js';
import { FakeAgy, PASS, newVault, tempDir } from './helpers.js';

describe('executable resolution (no binary planting)', () => {
  it('ignores the current directory and relative PATH entries', () => {
    const cwd = tempDir();
    const good = tempDir();
    const exe = process.platform === 'win32' ? 'agy.exe' : 'agy';
    fs.writeFileSync(path.join(cwd, exe), 'planted');
    fs.writeFileSync(path.join(good, exe), 'real', { mode: 0o755 });
    const sep = process.platform === 'win32' ? ';' : ':';
    const prev = process.cwd();
    process.chdir(cwd);
    try {
      const env = { PATH: ['.', '', 'relative/dir', good].join(sep) };
      expect(resolveExecutable('agy', env)).toBe(path.join(good, exe));
      expect(resolveExecutable('agy', { PATH: '.' })).toBeNull();
      expect(resolveExecutable('./agy', env)).toBeNull();
    } finally {
      process.chdir(prev);
    }
  });

  it.runIf(process.platform === 'win32')('prefers a real .exe over an npm .cmd shim on Windows', () => {
    const a = tempDir();
    const b = tempDir();
    fs.writeFileSync(path.join(a, 'agy.cmd'), '');
    fs.writeFileSync(path.join(b, 'agy.exe'), '');
    expect(resolveExecutable('agy', { PATH: `${a};${b}` }, 'win32')).toBe(path.win32.join(b, 'agy.exe'));
  });
});

describe('vault lock', () => {
  it('never takes over a lock whose owner is still alive, however old', async () => {
    const lock = path.join(tempDir(), '.lock');
    fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, at: 0 }));
    await expect(withLock(lock, async () => 1)).rejects.toMatchObject({ code: 'E_BUSY' });
  });
});

describe('interrupted operations', () => {
  it('blocks new operations until a pending rollback is resolved, so it is never overwritten', async () => {
    const fake = new FakeAgy();
    const { vault } = await newVault();
    const ctx: Ctx = { vault, provider: fake.provider() };
    fake.loginAs('bob');
    await addFromLive(ctx, 'bob');
    fake.loginAs('alice');
    await addFromLive(ctx, 'alice');
    // Simulate Ctrl+C during `add`: live store emptied, previous login only in the rollback record.
    await vault.writeRollback({ provider: 'agy', takenAt: 't', reason: 'add x', snapshot: await ctx.provider.readLive() });
    await ctx.provider.clearLive();
    const bob = requireProfile(vault.manifest, 'agy', 'bob');
    await expect(switchTo(ctx, bob)).rejects.toMatchObject({ code: 'E_PENDING_ROLLBACK' });
    await expect(lockLive(ctx)).rejects.toMatchObject({ code: 'E_PENDING_ROLLBACK' });
    expect((await vault.readRollback())?.reason).toBe('add x');
  });
});

describe('passphrase change re-keys the vault', () => {
  it('old passphrase + old vault.json cannot decrypt profiles written afterwards', async () => {
    const { vault, paths } = await newVault();
    await vault.writeProfile('aa11', { t: 'before' });
    vault.manifest.profiles.push({ id: 'aa11', name: 'x', provider: 'agy', fingerprint: 'f', createdAt: '', updatedAt: '' });
    await vault.saveManifest();
    const oldVaultJson = fs.readFileSync(paths.vault, 'utf8');

    await vault.changePassphrase('the new passphrase 42');
    await vault.writeProfile('aa11', { t: 'after' });
    vault.close();

    // Attacker: old vault.json + old passphrase -> old data key.
    const old = JSON.parse(oldVaultJson);
    const kek = await deriveKek(PASS, old.kdf);
    const { open } = await import('../src/vault/crypto.js');
    const oldVdk = open(kek, old.wrappedVdk, `ai-locker:${old.vaultId}:vdk:`);
    const blob = JSON.parse(fs.readFileSync(paths.profile('aa11'), 'utf8'));
    expect(() => open(subkey(oldVdk, 'profile', 'aa11'), blob, `ai-locker:${old.vaultId}:profile:aa11`)).toThrow();

    const v = await Vault.unlock(paths, { getPassphrase: async () => 'the new passphrase 42' });
    expect(await v.readProfile('aa11')).toEqual({ t: 'after' });
    expect(fs.readdirSync(paths.profilesDir).filter((f) => f.endsWith('.rekey'))).toEqual([]);
  });

  it('recovers from a crash before or after the commit point', async () => {
    const { vault, paths } = await newVault();
    await vault.writeProfile('bb22', { t: 1 });
    vault.manifest.profiles.push({ id: 'bb22', name: 'y', provider: 'agy', fingerprint: 'f', createdAt: '', updatedAt: '' });
    await vault.saveManifest();
    // Crash before commit: a staged file under some other key must be discarded.
    const junkKey = Buffer.alloc(32, 9);
    fs.writeFileSync(
      paths.profile('bb22') + '.rekey',
      JSON.stringify(sealJson(subkey(junkKey, 'profile', 'bb22'), { t: 'junk' }, 'x')),
    );
    vault.close();
    const v = await Vault.unlock(paths, { getPassphrase: async () => PASS });
    expect(await v.readProfile('bb22')).toEqual({ t: 1 });
    expect(fs.existsSync(paths.profile('bb22') + '.rekey')).toBe(false);
  });
});

describe('untrusted import files', () => {
  it('rejects absurd KDF parameters before deriving anything', async () => {
    const { vault } = await newVault();
    const evil = JSON.stringify({
      format: 'agyhub-export',
      v: 1,
      createdAt: '',
      kdf: { name: 'scrypt', N: 2 ** 30, r: 8, p: 1, salt: 'c2FsdHNhbHQ=' },
      payload: {},
    });
    await expect(importProfiles(vault, evil, 'whatever')).rejects.toMatchObject({ code: 'E_FORMAT' });
  });

  it('sanitises profile names from the bundle', async () => {
    const fake = new FakeAgy();
    const src = await newVault();
    fake.loginAs('alice');
    const meta = await addFromLive({ vault: src.vault, provider: fake.provider() }, 'alice');
    meta.name = '\x1b[31mevil\x1b[0m';
    const text = await exportProfiles(src.vault, [meta], 'export passphrase 1');
    const dst = await newVault();
    const res = await importProfiles(dst.vault, text, 'export passphrase 1');
    expect(res.imported[0]?.name).toBe('imported');
  });
});
