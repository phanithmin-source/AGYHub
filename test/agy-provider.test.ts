import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { AgyProvider } from '../src/providers/agy/index.js';
import { FileStore } from '../src/providers/agy/credentialStore.js';
import { parseJwtPayload } from '../src/providers/agy/jwt.js';
import { agyCreds, mockAgyJwt, tempDir } from './helpers.js';

describe('JWT parser', () => {
  it('parses valid JWT claims', () => {
    const jwt = mockAgyJwt('testuser', { hd: 'example.corp' });
    const claims = parseJwtPayload(jwt);
    expect(claims).not.toBeNull();
    expect(claims?.email).toBe('testuser@example.com');
    expect(claims?.sub).toBe('google-sub-testuser');
    expect(claims?.hd).toBe('example.corp');
  });

  it('handles invalid JWT strings safely', () => {
    expect(parseJwtPayload('')).toBeNull();
    expect(parseJwtPayload('invalid')).toBeNull();
    expect(parseJwtPayload('a.notbase64.c')).toBeNull();
  });
});

describe('AgyProvider', () => {
  function newTestProvider() {
    const dir = tempDir('agy-provider-test-');
    const credFile = path.join(dir, '.credentials.json');
    const store = new FileStore(credFile);
    const provider = new AgyProvider({
      store,
      env: {
        platform: 'linux',
        configDir: dir,
        keychainService: 'gemini',
        keychainAccount: 'antigravity',
        winTarget: 'gemini:antigravity',
      },
      findProcesses: async () => [],
    });
    return { dir, credFile, store, provider };
  }

  it('reports kind and location', () => {
    const { provider, credFile } = newTestProvider();
    const desc = provider.describeStore();
    expect(desc.kind).toBe('file');
    expect(desc.location).toBe(credFile);
  });

  it('reads null when file is missing', async () => {
    const { provider } = newTestProvider();
    expect(await provider.readLive()).toBeNull();
  });

  it('writes and reads live credentials', async () => {
    const { provider } = newTestProvider();
    const cred = agyCreds('alice');
    await provider.writeLive({
      v: 1,
      token: cred.token,
      auth_method: cred.auth_method,
      id_token: cred.id_token,
    });

    const read = await provider.readLive();
    expect(read).not.toBeNull();
    expect(read?.token.access_token).toBe('ya29.alice-access');
    expect(provider.hasLogin(read!)).toBe(true);
  });

  it('extracts identity from snapshot', async () => {
    const { provider } = newTestProvider();
    const cred = agyCreds('bob');
    const snap = {
      v: 1 as const,
      token: cred.token,
      auth_method: cred.auth_method,
      id_token: cred.id_token,
    };
    const id = provider.identity(snap);
    expect(id.email).toBe('bob@example.com');
    expect(id.accountKey).toBe('google-sub-bob');
    expect(id.plan).toBe('consumer');
    expect(typeof id.tokenExpiresAt).toBe('number');
  });

  it('generates a stable fingerprint that changes on token rotation', () => {
    const { provider } = newTestProvider();
    const credA = agyCreds('alice');
    const snap1 = { v: 1 as const, token: credA.token, auth_method: 'consumer', id_token: credA.id_token };
    const fp1 = provider.fingerprint(snap1);

    const snap1Same = { v: 1 as const, token: { ...credA.token }, auth_method: 'consumer', id_token: credA.id_token };
    expect(provider.fingerprint(snap1Same)).toBe(fp1);

    const snap2 = {
      v: 1 as const,
      token: { ...credA.token, refresh_token: '1//rotated-refresh' },
      auth_method: 'consumer',
      id_token: credA.id_token,
    };
    expect(provider.fingerprint(snap2)).not.toBe(fp1);
  });

  it('clears live store', async () => {
    const { provider } = newTestProvider();
    const cred = agyCreds('carol');
    await provider.writeLive({ v: 1, token: cred.token, auth_method: 'consumer', id_token: cred.id_token });
    expect(await provider.readLive()).not.toBeNull();
    await provider.clearLive();
    expect(await provider.readLive()).toBeNull();
  });

  it('verifies live login and detects email mismatch', async () => {
    const { provider } = newTestProvider();
    const cred = agyCreds('alice');
    await provider.writeLive({ v: 1, token: cred.token, auth_method: 'consumer', id_token: cred.id_token });

    const ok = await provider.verifyLive({ email: 'alice@example.com' });
    expect(ok.ok).toBe(true);

    const mismatch = await provider.verifyLive({ email: 'bob@example.com' });
    expect(mismatch.ok).toBe(false);
  });
});
