import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { addFromLive, addViaLogin, captureLive, lockLive, rollback, switchTo, type Ctx } from '../src/core/switchService.js';
import { requireProfile } from '../src/core/profiles.js';
import { exportProfiles, importProfiles } from '../src/core/transfer.js';
import { FakeAgy, newVault } from './helpers.js';

async function setup() {
  const fake = new FakeAgy();
  const { vault, paths } = await newVault();
  const ctx: Ctx = { vault, provider: fake.provider() };
  return { fake, vault, paths, ctx };
}

/** Two saved profiles, alice active. */
async function twoProfiles() {
  const s = await setup();
  s.fake.loginAs('bob');
  await addFromLive(s.ctx, 'bob');
  s.fake.loginAs('alice');
  await addFromLive(s.ctx, 'alice');
  return s;
}

describe('add --from-live', () => {
  it('saves the current login and makes it active', async () => {
    const { fake, vault, ctx } = await setup();
    fake.loginAs('alice');
    const meta = await addFromLive(ctx, 'work');
    expect(meta).toMatchObject({ name: 'work', email: 'alice@example.com', plan: 'consumer' });
    expect(vault.manifest.active['agy']).toBe(meta.id);
    expect(((await vault.readProfile(meta.id)) as any).token.refresh_token).toBe(
      '1//alice-refresh',
    );
  });

  it('refuses to save the same account twice', async () => {
    const { fake, ctx } = await setup();
    fake.loginAs('alice');
    await addFromLive(ctx, 'work');
    await expect(addFromLive(ctx, 'again')).rejects.toMatchObject({ code: 'E_EXISTS' });
  });

  it('fails when nothing is logged in', async () => {
    const { ctx } = await setup();
    await expect(addFromLive(ctx, 'x')).rejects.toMatchObject({ code: 'E_NO_LIVE' });
  });
});

describe('use', () => {
  it('swaps credentials cleanly', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    const res = await switchTo(ctx, requireProfile(vault.manifest, 'agy', 'bob'));
    expect(res.alreadyActive).toBe(false);
    expect(fake.liveCreds().token.refresh_token).toBe('1//bob-refresh');
    expect(vault.manifest.active['agy']).toBe(res.profile.id);
    expect(fs.existsSync(vault.paths.rollback)).toBe(false);
  });

  it('captures rotated tokens before switching away, and restores them when switching back', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    fake.rotate('alice', 7); // Antigravity refreshed alice's tokens while she was active
    const res = await switchTo(ctx, requireProfile(vault.manifest, 'agy', 'bob'));
    expect(res.capture.kind).toBe('updated');
    await switchTo(ctx, requireProfile(vault.manifest, 'agy', 'alice'));
    expect(fake.liveCreds().token.refresh_token).toBe('1//alice-refresh-r7');
  });

  it('recognises a rotated login by account key even if tokens changed', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    fake.rotate('alice', 1);
    fake.rotate('alice', 2);
    const cap = await captureLive(ctx);
    expect(cap.kind).toBe('updated');
    expect(vault.manifest.profiles).toHaveLength(2);
  });

  it('is a no-op when the target is already active', async () => {
    const { vault, ctx } = await twoProfiles();
    const res = await switchTo(ctx, requireProfile(vault.manifest, 'agy', 'alice'));
    expect(res.alreadyActive).toBe(true);
  });

  it('refuses while Antigravity is running unless forced', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    fake.running = [{ pid: 42, name: 'agy.exe' }];
    const bob = requireProfile(vault.manifest, 'agy', 'bob');
    await expect(switchTo(ctx, bob)).rejects.toMatchObject({ code: 'E_RUNNING' });
    expect(fake.liveCreds().token.refresh_token).toContain('alice');
    await switchTo(ctx, bob, { force: true });
    expect(fake.liveCreds().token.refresh_token).toContain('bob');
  });

  it('restores the previous login when verification fails', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    const before = fake.liveCreds();
    fake.verifyResult = { ok: false, detail: 'simulated failure' };
    await expect(switchTo(ctx, requireProfile(vault.manifest, 'agy', 'bob'))).rejects.toMatchObject({
      code: 'E_VERIFY',
    });
    expect(fake.liveCreds()).toEqual(before);
    expect(vault.manifest.active['agy']).toBe(requireProfile(vault.manifest, 'agy', 'alice').id);
  });

  it('refuses to overwrite an unsaved login, or saves/discards it on request', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    fake.loginAs('carol'); // logged in outside agyhub
    const bob = requireProfile(vault.manifest, 'agy', 'bob');
    await expect(switchTo(ctx, bob)).rejects.toMatchObject({ code: 'E_UNSAVED_LIVE' });
    expect(fake.liveCreds().token.refresh_token).toContain('carol');

    const res = await switchTo(ctx, bob, { saveUnknownAs: 'carol' });
    expect(res.capture.kind).toBe('saved-new');
    expect(requireProfile(vault.manifest, 'agy', 'carol').email).toBe('carol@example.com');

    fake.loginAs('dave');
    const r2 = await switchTo(ctx, bob, { discardLive: true });
    expect(r2.capture.kind).toBe('discarded');
    expect(vault.manifest.profiles.map((p) => p.name).sort()).toEqual(['alice', 'bob', 'carol']);
  });

  it('asks interactively about an unsaved login', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    fake.loginAs('erin');
    await switchTo(ctx, requireProfile(vault.manifest, 'agy', 'bob'), {
      onUnknown: async (id) => (id.email === 'erin@example.com' ? 'erin' : null),
    });
    expect(requireProfile(vault.manifest, 'agy', 'erin')).toBeTruthy();
  });

  it('refuses to switch when a profile blob was tampered with, leaving the live login intact', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    const bob = requireProfile(vault.manifest, 'agy', 'bob');
    const file = vault.paths.profile(bob.id);
    const sealed = JSON.parse(fs.readFileSync(file, 'utf8'));
    sealed.tag = Buffer.alloc(16).toString('base64');
    fs.writeFileSync(file, JSON.stringify(sealed));
    await expect(switchTo(ctx, bob)).rejects.toMatchObject({ code: 'E_DECRYPT' });
    expect(fake.liveCreds().token.refresh_token).toContain('alice');
  });
});

describe('add via login', () => {
  it('saves the current login, lets Antigravity log in fresh, then stores the new account', async () => {
    const { fake, vault, ctx } = await setup();
    fake.loginAs('alice');
    await addFromLive(ctx, 'alice');
    fake.rotate('alice', 3);
    fake.nextLogin = 'bob';
    const res = await addViaLogin(ctx, 'bob');
    expect(res.capture.kind).toBe('updated');
    expect(res.profile.email).toBe('bob@example.com');
    expect(fake.liveCreds().token.refresh_token).toContain('bob');
    const alice = requireProfile(vault.manifest, 'agy', 'alice');
    expect(((await vault.readProfile(alice.id)) as any).token.refresh_token).toBe(
      '1//alice-refresh-r3',
    );
  });

  it('restores the previous login when the login step fails', async () => {
    const { fake, ctx } = await setup();
    fake.loginAs('alice');
    await addFromLive(ctx, 'alice');
    const before = fake.liveCreds();
    fake.nextLogin = null; // login exits non-zero
    await expect(addViaLogin(ctx, 'bob')).rejects.toMatchObject({ code: 'E_LOGIN' });
    expect(fake.liveCreds()).toEqual(before);
  });

  it('removes the half-created profile when verification fails after login', async () => {
    const { fake, vault, ctx } = await setup();
    fake.loginAs('alice');
    await addFromLive(ctx, 'alice');
    fake.nextLogin = 'bob';
    fake.verifyResult = { ok: false, detail: 'simulated' };
    await expect(addViaLogin(ctx, 'bob')).rejects.toMatchObject({ code: 'E_VERIFY' });
    expect(vault.manifest.profiles.map((p) => p.name)).toEqual(['alice']);
    expect(fs.readdirSync(vault.paths.profilesDir)).toHaveLength(1);
    expect(fake.liveCreds().token.refresh_token).toContain('alice');
  });

  it('recognises an account that is already saved', async () => {
    const { fake, vault, ctx } = await setup();
    fake.loginAs('alice');
    await addFromLive(ctx, 'alice');
    fake.nextLogin = 'alice';
    const res = await addViaLogin(ctx, 'alice2');
    expect(res.duplicateOf?.name).toBe('alice');
    expect(vault.manifest.profiles).toHaveLength(1);
  });

  it('supports the manual flow', async () => {
    const { fake, ctx } = await setup();
    const res = await addViaLogin(ctx, 'bob', {
      manual: async () => {
        expect(fake.liveCreds()).toBeNull();
        fake.loginAs('bob');
      },
    });
    expect(res.profile.email).toBe('bob@example.com');
  });
});

describe('lock / unlock / rollback', () => {
  it('lock moves the login into the vault and logs Antigravity out', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    fake.rotate('alice', 9);
    const cap = await lockLive(ctx);
    expect(cap.kind).toBe('updated');
    expect(fake.liveCreds()).toBeNull();
    expect(vault.manifest.active['agy']).toBeNull();
    const alice = requireProfile(vault.manifest, 'agy', 'alice');
    expect(vault.manifest.lastActive['agy']).toBe(alice.id);
    await switchTo(ctx, alice);
    expect(fake.liveCreds().token.refresh_token).toBe('1//alice-refresh-r9');
  });

  it('rollback restores the login captured before an interrupted operation', async () => {
    const { fake, vault, ctx } = await twoProfiles();
    const before = fake.liveCreds();
    await vault.writeRollback({ provider: 'agy', takenAt: 't', reason: 'use bob', snapshot: await ctx.provider.readLive() });
    fake.loginAs('bob');
    const res = await rollback(ctx);
    expect(res?.reason).toBe('use bob');
    expect(fake.liveCreds()).toEqual(before);
    expect(await vault.readRollback()).toBeNull();
  });
});

describe('export / import', () => {
  it('round-trips profiles through a separately encrypted file', async () => {
    const { vault } = await twoProfiles();
    const text = await exportProfiles(vault, vault.manifest.profiles, 'export passphrase 1');
    expect(text).not.toContain('ya29');
    expect(text).not.toContain('alice');

    const other = await setup();
    await expect(importProfiles(other.vault, text, 'wrong passphrase!')).rejects.toMatchObject({ code: 'E_BAD_PASSPHRASE' });
    const res = await importProfiles(other.vault, text, 'export passphrase 1');
    expect(res.imported.map((p) => p.name).sort()).toEqual(['alice', 'bob']);
    const again = await importProfiles(other.vault, text, 'export passphrase 1');
    expect(again.imported).toHaveLength(0);
    expect(again.skipped).toHaveLength(2);

    const bob = requireProfile(other.vault.manifest, 'agy', 'bob');
    await switchTo(other.ctx, bob);
    expect(other.fake.liveCreds().token.refresh_token).toBe('1//bob-refresh');
  });
});
