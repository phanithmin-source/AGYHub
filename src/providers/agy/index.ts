import path from 'node:path';
import { LockerError } from '../../util/errors.js';
import { resolveExecutable, run, runInteractive } from '../../util/exec.js';
import { sha256Hex } from '../../vault/crypto.js';
import type { DoctorCheck, Identity, LoginOptions, Provider, RunningProcess, VerifyResult } from '../Provider.js';
import { CredentialStore, FileStore, KeychainStore, LinuxSecretStore, Win32CredStore } from './credentialStore.js';
import { cleanAgyEnv, OVERRIDING_ENV_VARS, resolveAgyEnv, type AgyEnv } from './env.js';
import { parseJwtPayload } from './jwt.js';
import { findAgyProcesses } from './process.js';

export function validateLoginEmail(email: string): string {
  if (!/^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$/.test(email)) {
    throw new LockerError(`"${email}" does not look like an email address.`, 'E_ARGS');
  }
  return email;
}

export interface AgySnapshot {
  v: 1;
  token: {
    access_token?: string;
    token_type?: string;
    refresh_token?: string;
    expiry?: string;
    [key: string]: unknown;
  };
  auth_method?: string;
  id_token?: string;
}

export interface AgyProviderOptions {
  env?: AgyEnv;
  store?: CredentialStore;
  agyBin?: string;
  findProcesses?: () => Promise<RunningProcess[]>;
}

export class AgyProvider implements Provider<AgySnapshot> {
  readonly id = 'agy';
  readonly displayName = 'Antigravity';
  readonly env: AgyEnv;
  private readonly store: CredentialStore;
  private readonly agyBin: string;
  private readonly findProcesses: () => Promise<RunningProcess[]>;

  constructor(opts: AgyProviderOptions = {}) {
    this.env = opts.env ?? resolveAgyEnv();
    const fallbackFile = new FileStore(path.join(this.env.configDir, '.credentials.json'));
    if (opts.store) {
      this.store = opts.store;
    } else if (this.env.platform === 'win32') {
      this.store = new Win32CredStore(this.env.winTarget, this.env.keychainAccount);
    } else if (this.env.platform === 'darwin') {
      this.store = new KeychainStore(this.env.keychainService, this.env.keychainAccount, fallbackFile);
    } else {
      this.store = new LinuxSecretStore(this.env.keychainService, this.env.keychainAccount, fallbackFile);
    }
    this.agyBin = opts.agyBin ?? process.env.AI_LOCKER_AGY_BIN ?? 'agy';
    this.findProcesses = opts.findProcesses ?? (() => findAgyProcesses(this.env.platform));
  }

  describeStore() {
    return { kind: this.store.kind, location: this.store.location };
  }

  async readLive(): Promise<AgySnapshot | null> {
    const text = await this.store.read();
    if (text === null || !text.trim()) return null;
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      throw new LockerError(
        `Antigravity credentials in ${this.store.location} are not valid JSON; refusing to touch them.`,
        'E_STORE',
      );
    }
    return {
      v: 1,
      token: data.token ?? {},
      auth_method: data.auth_method,
      id_token: data.id_token,
    };
  }

  async writeLive(snapshot: AgySnapshot): Promise<void> {
    const payload = {
      token: snapshot.token,
      auth_method: snapshot.auth_method,
      id_token: snapshot.id_token,
    };
    await this.store.write(JSON.stringify(payload));
  }

  async clearLive(): Promise<void> {
    await this.store.clear();
  }

  hasLogin(snapshot: AgySnapshot): boolean {
    const t = snapshot?.token;
    return Boolean(t && (t.accessToken || t.refreshToken || t.access_token || t.refresh_token));
  }

  fingerprint(snapshot: AgySnapshot): string {
    const t = snapshot?.token ?? {};
    const material = t.refreshToken || t.refresh_token || t.accessToken || t.access_token || JSON.stringify(snapshot);
    return sha256Hex(`agyhub-fp:${material}`).slice(0, 16);
  }

  identity(snapshot: AgySnapshot): Identity {
    const claims = snapshot.id_token ? parseJwtPayload(snapshot.id_token) : null;
    const t = snapshot.token ?? {};
    const expiryStr = typeof t.expiry === 'string' ? t.expiry : undefined;
    const tokenExpiresAt = expiryStr ? Date.parse(expiryStr) : undefined;
    const exp = typeof claims?.exp === 'number' ? claims.exp * 1000 : undefined;

    return {
      accountKey: claims?.sub,
      email: claims?.email,
      organization: claims?.hd,
      plan: snapshot.auth_method ?? (claims ? 'consumer' : undefined),
      tokenExpiresAt: Number.isFinite(tokenExpiresAt) ? tokenExpiresAt : undefined,
      refreshExpiresAt: Number.isFinite(exp) ? exp : undefined,
    };
  }

  runningProcesses(): Promise<RunningProcess[]> {
    return this.findProcesses();
  }

  private agyExecutable(): string | null {
    return resolveExecutable(this.agyBin);
  }

  async verifyLive(expected?: Identity): Promise<VerifyResult> {
    const live = await this.readLive();
    if (!live || !this.hasLogin(live)) {
      return { ok: false, detail: 'Antigravity reports it is not logged in' };
    }
    const id = this.identity(live);
    if (expected?.email && id.email && id.email.toLowerCase() !== expected.email.toLowerCase()) {
      return { ok: false, email: id.email, detail: `Antigravity active login is ${id.email}, expected ${expected.email}` };
    }
    const email = id.email;
    const method = live.auth_method ?? 'authenticated';
    return {
      ok: true,
      email,
      detail: `logged in${email ? ` as ${email}` : ''} (${method})`,
    };
  }

  async login(_opts: LoginOptions): Promise<number> {
    void _opts;
    const bin = this.agyExecutable();
    if (!bin) {
      throw new LockerError('Could not find `agy`. Is Antigravity CLI installed and on PATH?', 'E_NO_AGY');
    }
    // `agy` without arguments triggers the interactive session / login flow if not authenticated
    return runInteractive(bin, [], { env: cleanAgyEnv() });
  }

  async doctor(): Promise<DoctorCheck[]> {
    const checks: DoctorCheck[] = [];
    const bin = this.agyExecutable();
    if (!bin) {
      checks.push({ name: 'Antigravity CLI', status: 'warn', detail: '`agy` not found on PATH' });
    } else {
      const v = await run(bin, ['--version'], { timeoutMs: 30_000 });
      checks.push(
        v.code === 0
          ? { name: 'Antigravity CLI', status: 'ok', detail: `${v.stdout.trim()} at ${bin}` }
          : { name: 'Antigravity CLI', status: 'warn', detail: `\`${bin} --version\` failed` },
      );
    }

    checks.push({ name: 'Config directory', status: 'info', detail: this.env.configDir });
    checks.push({ name: 'Credential store', status: 'info', detail: `${this.store.kind}: ${this.store.location}` });

    const live = await this.readLive().catch((err: Error) => err);
    if (live instanceof Error) {
      checks.push({ name: 'Live login', status: 'fail', detail: live.message });
    } else if (!live || !this.hasLogin(live)) {
      checks.push({ name: 'Live login', status: 'info', detail: 'none' });
    } else {
      const id = this.identity(live);
      checks.push({
        name: 'Live login',
        status: 'ok',
        detail: `${id.email ?? 'unknown email'} (${id.plan ?? 'unknown method'})`,
      });
    }

    for (const k of OVERRIDING_ENV_VARS) {
      if (process.env[k]) {
        checks.push({
          name: k,
          status: 'warn',
          detail: 'is set; Antigravity will use it instead of the stored login, so switching has no visible effect',
        });
      }
    }

    return checks;
  }
}
