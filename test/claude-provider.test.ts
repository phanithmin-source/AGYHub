import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { keychainServiceName, resolveClaudeEnv } from '../src/providers/claude-code/env.js';
import { IdentityStore } from '../src/providers/claude-code/identityStore.js';
import { isClaudeProcess } from '../src/providers/claude-code/process.js';
import { parseUsage, fetchUsage } from '../src/providers/claude-code/usage.js';
import { FakeClaude, account, creds } from './helpers.js';
import path from 'node:path';
import os from 'node:os';

describe('Claude Code env', () => {
  it('uses ~/.claude and ~/.claude.json by default', () => {
    const env = resolveClaudeEnv({}, 'win32');
    expect(env.configDir).toBe(path.join(os.homedir(), '.claude'));
    expect(env.globalConfigPath).toBe(path.join(os.homedir(), '.claude.json'));
  });

  it('puts both files under CLAUDE_CONFIG_DIR when set', () => {
    const env = resolveClaudeEnv({ CLAUDE_CONFIG_DIR: '/tmp/cc' }, 'linux');
    expect(env.configDir).toBe('/tmp/cc');
    expect(env.globalConfigPath).toBe(path.join('/tmp/cc', '.claude.json'));
  });

  it('derives the macOS Keychain service name like Claude Code', () => {
    expect(keychainServiceName({})).toBe('Claude Code-credentials');
    // sha256("/Users/me/.claude-work") first 8 hex chars
    expect(keychainServiceName({ CLAUDE_CONFIG_DIR: '/Users/me/.claude-work' })).toMatch(/^Claude Code-credentials-[0-9a-f]{8}$/);
    expect(keychainServiceName({ CLAUDE_CONFIG_DIR: '/a', CLAUDE_SECURESTORAGE_CONFIG_DIR: '' })).toBe('Claude Code-credentials');
    expect(keychainServiceName({ CLAUDE_CONFIG_DIR: '/a', CLAUDE_SECURESTORAGE_CONFIG_DIR: '/b' })).toBe(
      keychainServiceName({ CLAUDE_CONFIG_DIR: '/b' }),
    );
    // NFC normalisation: composed and decomposed paths hash the same
    expect(keychainServiceName({ CLAUDE_CONFIG_DIR: '/Users/caf\u00e9' })).toBe(
      keychainServiceName({ CLAUDE_CONFIG_DIR: '/Users/cafe\u0301' }),
    );
  });
});

describe('IdentityStore', () => {
  it('replaces only oauthAccount and keeps everything else, including order and indent', async () => {
    const fake = new FakeClaude();
    fake.loginAs('alice');
    const before = fake.globalJson();
    const store = new IdentityStore(fake.globalConfig);
    await store.write(account('bob'));
    const after = fake.globalJson();
    expect(after.oauthAccount.emailAddress).toBe('bob@example.com');
    expect(Object.keys(after)).toEqual(Object.keys(before));
    expect(after.projects).toEqual(before.projects);
    const raw = fs.readFileSync(fake.globalConfig, 'utf8');
    expect(raw.startsWith('{\n  "')).toBe(true);
    expect(raw.endsWith('\n')).toBe(true);
    await store.write(null);
    expect(fake.globalJson().oauthAccount).toBeUndefined();
    expect(fake.globalJson().userID).toBe('device-1');
  });

  it('refuses to modify an invalid JSON file', async () => {
    const fake = new FakeClaude();
    fs.writeFileSync(fake.globalConfig, '{ not json');
    await expect(new IdentityStore(fake.globalConfig).write(account('x'))).rejects.toMatchObject({ code: 'E_CLAUDE_CONFIG' });
    expect(fs.readFileSync(fake.globalConfig, 'utf8')).toBe('{ not json');
  });
});

describe('ClaudeCodeProvider (file store)', () => {
  it('reads, identifies, clears and writes the live login', async () => {
    const fake = new FakeClaude();
    const p = fake.provider();
    expect(await p.readLive()).toBeNull();

    fake.loginAs('alice');
    const snap = (await p.readLive())!;
    expect(p.hasLogin(snap)).toBe(true);
    expect(p.identity(snap)).toMatchObject({
      email: 'alice@example.com',
      plan: 'max',
      accountKey: 'acct-alice:org-alice',
    });

    await p.clearLive();
    expect(fake.liveCreds()).toBeNull();
    expect(fake.globalJson().oauthAccount).toBeUndefined();

    await p.writeLive(snap);
    expect(fake.liveCreds()).toEqual(creds('alice', { claudeAiOauth: fake.liveCreds().claudeAiOauth }));
    expect(fake.globalJson().oauthAccount.emailAddress).toBe('alice@example.com');
  });

  it('fingerprint changes on token rotation while the account key stays', async () => {
    const fake = new FakeClaude();
    const p = fake.provider();
    fake.loginAs('alice');
    const a = (await p.readLive())!;
    fake.rotate('alice', 1);
    const b = (await p.readLive())!;
    expect(p.fingerprint(a)).not.toBe(p.fingerprint(b));
    expect(p.identity(a).accountKey).toBe(p.identity(b).accountKey);
    expect(p.fingerprint(a)).not.toContain('sk-ant');
  });

  it('treats a credentials file without claudeAiOauth as no login', async () => {
    const fake = new FakeClaude();
    fs.writeFileSync(fake.credFile, JSON.stringify({ mcpOAuth: { x: {} } }));
    const snap = await fake.provider().readLive();
    expect(snap).not.toBeNull();
    expect(fake.provider().hasLogin(snap!)).toBe(false);
  });

  it('refuses to touch an invalid credentials file', async () => {
    const fake = new FakeClaude();
    fs.writeFileSync(fake.credFile, '{oops');
    await expect(fake.provider().readLive()).rejects.toMatchObject({ code: 'E_STORE' });
  });

  it.runIf(process.platform !== 'win32')('writes credentials with mode 0600', async () => {
    const fake = new FakeClaude();
    fake.loginAs('alice');
    const p = fake.provider();
    const snap = (await p.readLive())!;
    await p.clearLive();
    await p.writeLive(snap);
    expect(fs.statSync(fake.credFile).mode & 0o777).toBe(0o600);
  });
});

describe('process detection', () => {
  it('recognises native and npm-installed Claude Code', () => {
    expect(isClaudeProcess({ pid: 1, name: 'claude.exe', commandLine: '' })).toBe(true);
    expect(isClaudeProcess({ pid: 1, name: '/usr/local/bin/claude', commandLine: 'claude' })).toBe(true);
    expect(
      isClaudeProcess({ pid: 1, name: 'node.exe', commandLine: 'node C:\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js' }),
    ).toBe(true);
    expect(isClaudeProcess({ pid: 1, name: 'node', commandLine: 'node /x/agyhub/dist/cli.js use work' })).toBe(false);
    expect(isClaudeProcess({ pid: 1, name: '/Applications/Claude.app/Contents/MacOS/Claude', commandLine: '' })).toBe(false);
    expect(
      isClaudeProcess({
        pid: 1,
        name: 'claude.exe',
        commandLine: '"C:\\Users\\me\\AppData\\Local\\AnthropicClaude\\app-1.2.3\\claude.exe" --type=renderer',
      }),
    ).toBe(false);
    expect(isClaudeProcess({ pid: 1, name: 'claude.exe', commandLine: 'C:\\Users\\me\\.local\\bin\\claude.exe' })).toBe(true);
  });
});

describe('usage parsing', () => {
  it('parses the limits[] shape', () => {
    const w = parseUsage({
      limits: [
        { kind: 'session', percent: 12.5, resets_at: '2026-10-14T12:00:00Z' },
        { kind: 'weekly_all', percent: 40, resets_at: null },
        { kind: 'weekly_scoped', percent: 3, scope: { model: { display_name: 'Fable' } } },
      ],
    });
    expect(w.map((x) => x.label)).toEqual(['Session', 'Weekly (all models)', 'Weekly (Fable)']);
    expect(w[0]).toMatchObject({ percent: 12.5, resetsAt: '2026-10-14T12:00:00Z' });
  });

  it('parses the legacy flat shape and tolerates nulls', () => {
    const w = parseUsage({ five_hour: { utilization: 4, resets_at: 'x' }, seven_day: null, seven_day_opus: { utilization: null } });
    expect(w).toEqual([{ label: '5-hour', percent: 4, resetsAt: 'x' }]);
    expect(parseUsage(null)).toEqual([]);
    expect(parseUsage({ unknown: true })).toEqual([]);
  });

  it('sends the token only to the Anthropic endpoint and reports HTTP errors', async () => {
    const calls: [string, RequestInit][] = [];
    const ok = await fetchUsage('tok', (async (url: string, init: RequestInit) => {
      calls.push([url, init]);
      return new Response(JSON.stringify({ limits: [{ kind: 'session', percent: 1 }] }), { status: 200 });
    }) as unknown as typeof fetch);
    expect(ok.ok).toBe(true);
    expect(calls[0]?.[0]).toBe('https://api.anthropic.com/api/oauth/usage');
    const res401 = await fetchUsage('tok', (async () => new Response('', { status: 401 })) as unknown as typeof fetch);
    expect(res401).toMatchObject({ ok: false, error: 'token rejected (401)' });
  });
});
