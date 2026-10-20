import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Vault } from '../src/vault/vault.js';
import { withLock } from '../src/vault/lock.js';
import { FAST_KDF, PASS, newVault, tempDir } from './helpers.js';
import { lockerPaths } from '../src/util/paths.js';
import path from 'node:path';

const fixed = (p: string) => async () => p;

describe('Vault', () => {
  it('creates, persists and unlocks with the passphrase', async () => {
    const { vault, paths } = await newVault();
    await vault.writeProfile('abc', { secret: 'token-123' });
    vault.manifest.profiles.push({
      id: 'abc',
      name: 'work',
      provider: 'agy',
      fingerprint: 'f',
      createdAt: '',
      updatedAt: '',
    });
    await vault.saveManifest();
    vault.close();

    const again = await Vault.unlock(paths, { getPassphrase: fixed(PASS) });
    expect(again.manifest.profiles.map((p) => p.name)).toEqual(['work']);
    expect(await again.readProfile('abc')).toEqual({ secret: 'token-123' });
    expect(again.unlockedVia).toBe('passphrase');
  });

  it('never stores secrets or profile names in plaintext', async () => {
    const { vault, paths } = await newVault();
    await vault.writeProfile('abc', { secret: 'ya29.very-secret-token' });
    vault.manifest.profiles.push({ id: 'abc', name: 'my-work-name', provider: 'agy', fingerprint: 'f', createdAt: '', updatedAt: '', email: 'me@corp.com' });
    await vault.saveManifest();
    const all = [paths.vault, paths.profile('abc')].map((f) => fs.readFileSync(f, 'utf8')).join('\n');
    expect(all).not.toContain('ya29');
    expect(all).not.toContain('my-work-name');
    expect(all).not.toContain('me@corp.com');
  });

  it('rejects a wrong passphrase after the allowed attempts', async () => {
    const { paths } = await newVault();
    let calls = 0;
    await expect(
      Vault.unlock(paths, { getPassphrase: async () => (calls++, 'wrong passphrase!!'), maxAttempts: 3 }),
    ).rejects.toMatchObject({ code: 'E_BAD_PASSPHRASE' });
    expect(calls).toBe(3);
  });

  it('accepts the passphrase on a later attempt', async () => {
    const { paths } = await newVault();
    const answers = ['nope nope nope', PASS];
    const v = await Vault.unlock(paths, { getPassphrase: async (n) => answers[n - 1] ?? null });
    expect(v.unlockedVia).toBe('passphrase');
  });

  it('refuses weak passphrases', async () => {
    const paths = lockerPaths(path.join(tempDir(), 'l'));
    await expect(Vault.create(paths, 'short', { osUnlock: false, kdf: FAST_KDF })).rejects.toMatchObject({
      code: 'E_WEAK_PASSPHRASE',
    });
  });

  it('changes the passphrase and re-encrypts every profile under a new data key', async () => {
    const { vault, paths } = await newVault();
    await vault.writeProfile('p1', { t: 1 });
    vault.manifest.profiles.push({ id: 'p1', name: 'p', provider: 'agy', fingerprint: 'f', createdAt: '', updatedAt: '' });
    await vault.saveManifest();
    const before = fs.readFileSync(paths.profile('p1'), 'utf8');
    await vault.changePassphrase('a brand new passphrase');
    vault.close();
    expect(fs.readFileSync(paths.profile('p1'), 'utf8')).not.toBe(before);
    await expect(Vault.unlock(paths, { getPassphrase: fixed(PASS), maxAttempts: 1 })).rejects.toMatchObject({
      code: 'E_BAD_PASSPHRASE',
    });
    const v = await Vault.unlock(paths, { getPassphrase: fixed('a brand new passphrase') });
    expect(await v.readProfile('p1')).toEqual({ t: 1 });
  });

  it('detects a tampered profile file', async () => {
    const { vault, paths } = await newVault();
    await vault.writeProfile('p1', { t: 1 });
    const sealed = JSON.parse(fs.readFileSync(paths.profile('p1'), 'utf8'));
    const ct = Buffer.from(sealed.ct, 'base64');
    ct[0] = (ct[0] ?? 0) ^ 0xff;
    sealed.ct = ct.toString('base64');
    fs.writeFileSync(paths.profile('p1'), JSON.stringify(sealed));
    await expect(vault.readProfile('p1')).rejects.toMatchObject({ code: 'E_DECRYPT' });
  });

  it('binds each profile blob to its id (no swapping files between profiles)', async () => {
    const { vault, paths } = await newVault();
    await vault.writeProfile('aaa', { who: 'a' });
    await vault.writeProfile('bbb', { who: 'b' });
    fs.copyFileSync(paths.profile('aaa'), paths.profile('bbb'));
    await expect(vault.readProfile('bbb')).rejects.toMatchObject({ code: 'E_DECRYPT' });
  });

  it('stores and clears the rollback record', async () => {
    const { vault } = await newVault();
    expect(await vault.readRollback()).toBeNull();
    await vault.writeRollback({ provider: 'agy', takenAt: 'now', reason: 'test', snapshot: { x: 1 } });
    expect((await vault.readRollback())?.snapshot).toEqual({ x: 1 });
    await vault.clearRollback();
    expect(await vault.readRollback()).toBeNull();
  });

  it.runIf(process.platform === 'win32')('unlocks via Windows DPAPI without the passphrase', async () => {
    const { vault, paths } = await newVault();
    await vault.enableOsUnlock();
    vault.close();
    expect(fs.readFileSync(paths.osUnlockBlob, 'utf8')).not.toHaveLength(0);
    const v = await Vault.unlock(paths, { getPassphrase: async () => { throw new Error('should not prompt'); } });
    expect(v.unlockedVia).toBe('os');
    // --strict ignores the OS cache
    const strict = await Vault.unlock(paths, { getPassphrase: fixed(PASS), strict: true });
    expect(strict.unlockedVia).toBe('passphrase');
    await strict.disableOsUnlock();
    expect(fs.existsSync(paths.osUnlockBlob)).toBe(false);
  });

  it.runIf(process.platform === 'win32')('falls back to the passphrase when the DPAPI blob is corrupt', async () => {
    const { vault, paths } = await newVault();
    await vault.enableOsUnlock();
    vault.close();
    fs.writeFileSync(paths.osUnlockBlob, Buffer.from('garbage').toString('base64'));
    const v = await Vault.unlock(paths, { getPassphrase: fixed(PASS) });
    expect(v.unlockedVia).toBe('passphrase');
  });
});

describe('withLock', () => {
  it('rejects a concurrent holder and recovers stale locks', async () => {
    const dir = tempDir();
    const lock = path.join(dir, '.lock');
    await withLock(lock, async () => {
      await expect(withLock(lock, async () => 1)).rejects.toMatchObject({ code: 'E_BUSY' });
    });
    fs.writeFileSync(lock, JSON.stringify({ pid: 999999, at: Date.now() }));
    expect(await withLock(lock, async () => 'ok')).toBe('ok');
    expect(fs.existsSync(lock)).toBe(false);
  });
});
