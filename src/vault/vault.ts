import fs from 'node:fs';
import crypto from 'node:crypto';
import { atomicWrite, readIfExists, removeIfExists } from './atomicWrite.js';
import { defaultKdf, deriveKek, open, openJson, randomId, seal, sealJson, subkey, type KdfParams, type Sealed } from './crypto.js';
import { ensurePrivateDir } from './perms.js';
import { osKeyCache, type OsKeyCache } from './osUnlock/index.js';
import { LockerError } from '../util/errors.js';
import type { LockerPaths } from '../util/paths.js';

export interface ProfileMeta {
  id: string;
  name: string;
  provider: string;
  /** Stable account identity used to recognise the same login after token rotation. */
  accountKey?: string;
  email?: string;
  organization?: string;
  plan?: string;
  /** Short hash of the refresh token at last capture (never the token itself). */
  fingerprint: string;
  tokenExpiresAt?: number;
  refreshExpiresAt?: number;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
}

export interface Manifest {
  profiles: ProfileMeta[];
  /** provider id -> profile id currently written into that provider's live store. */
  active: Record<string, string | null>;
  /** provider id -> profile that was active before `lock`, used by `unlock`. */
  lastActive: Record<string, string | null>;
}

export interface RollbackRecord {
  provider: string;
  takenAt: string;
  reason: string;
  /** null means the live store was empty before the operation. */
  snapshot: unknown | null;
}

interface VaultFile {
  format: 'agyhub-vault' | 'ai-locker-vault';
  schema: 1;
  vaultId: string;
  createdAt: string;
  kdf: KdfParams;
  wrappedVdk: Sealed;
  osUnlock: boolean;
  manifest: Sealed;
}

export interface UnlockOptions {
  /** Called when the passphrase is needed. Return null to abort. */
  getPassphrase: (attempt: number) => Promise<string | null>;
  /** Ignore the OS-bound key cache and require the passphrase. */
  strict?: boolean;
  maxAttempts?: number;
}

export const MIN_PASSPHRASE_LENGTH = 12;

const aad = (vaultId: string, purpose: string, id = '') => `ai-locker:${vaultId}:${purpose}:${id}`;
const REKEY = '.rekey';

export class Vault {
  private constructor(
    readonly paths: LockerPaths,
    private file: VaultFile,
    private vdk: Buffer,
    public manifest: Manifest,
    readonly unlockedVia: 'passphrase' | 'os',
  ) {}

  get id(): string {
    return this.file.vaultId;
  }

  get osUnlockEnabled(): boolean {
    return this.file.osUnlock;
  }

  get kdf(): KdfParams {
    return this.file.kdf;
  }

  static exists(paths: LockerPaths): boolean {
    return fs.existsSync(paths.vault);
  }

  static osCache(paths: LockerPaths): OsKeyCache | null {
    return osKeyCache(paths.osUnlockBlob);
  }

  static async create(
    paths: LockerPaths,
    passphrase: string,
    opts: { osUnlock: boolean; kdf?: KdfParams },
  ): Promise<{ vault: Vault; hardened: boolean; osUnlockError?: string }> {
    if (Vault.exists(paths)) {
      throw new LockerError(`A vault already exists at ${paths.vault}.`, 'E_EXISTS');
    }
    checkPassphrase(passphrase);
    const { hardened } = ensurePrivateDir(paths.home);
    fs.mkdirSync(paths.profilesDir, { recursive: true, mode: 0o700 });

    const vaultId = randomId(16);
    const kdf = opts.kdf ?? defaultKdf();
    const kek = await deriveKek(passphrase, kdf);
    const vdk = crypto.randomBytes(32);
    const manifest: Manifest = { profiles: [], active: {}, lastActive: {} };
    const file: VaultFile = {
      format: 'agyhub-vault',
      schema: 1,
      vaultId,
      createdAt: new Date().toISOString(),
      kdf,
      wrappedVdk: seal(kek, vdk, aad(vaultId, 'vdk')),
      osUnlock: false,
      manifest: sealJson(subkey(vdk, 'manifest'), manifest, aad(vaultId, 'manifest')),
    };
    kek.fill(0);
    const vault = new Vault(paths, file, vdk, manifest, 'passphrase');
    await vault.writeFile();

    let osUnlockError: string | undefined;
    if (opts.osUnlock) {
      try {
        await vault.enableOsUnlock();
      } catch (err) {
        osUnlockError = (err as Error).message;
      }
    }
    await vault.audit('init');
    return { vault, hardened, osUnlockError };
  }

  static async unlock(paths: LockerPaths, opts: UnlockOptions): Promise<Vault> {
    const raw = await readIfExists(paths.vault);
    if (raw === null) {
      throw new LockerError('No vault found.', 'E_NO_VAULT', 'Run `agyhub init` first.');
    }
    const file = parseVaultFile(raw);

    if (file.osUnlock && !opts.strict) {
      const cache = Vault.osCache(paths);
      try {
        const vdk = cache ? await cache.load(file.vaultId) : null;
        if (vdk) {
          const manifest = openJson<Manifest>(subkey(vdk, 'manifest'), file.manifest, aad(file.vaultId, 'manifest'));
          const vault = new Vault(paths, file, vdk, normalizeManifest(manifest), 'os');
          await vault.finishRekey();
          return vault;
        }
      } catch {
        // A stale or foreign OS cache is not fatal: fall through to the passphrase.
      }
    }

    const max = opts.maxAttempts ?? 3;
    for (let attempt = 1; attempt <= max; attempt++) {
      const pass = await opts.getPassphrase(attempt);
      if (pass === null) throw new LockerError('Unlock cancelled.', 'E_CANCELLED');
      const kek = await deriveKek(pass, file.kdf);
      try {
        const vdk = open(kek, file.wrappedVdk, aad(file.vaultId, 'vdk'));
        const manifest = openJson<Manifest>(subkey(vdk, 'manifest'), file.manifest, aad(file.vaultId, 'manifest'));
        const vault = new Vault(paths, file, vdk, normalizeManifest(manifest), 'passphrase');
        await vault.finishRekey();
        return vault;
      } catch (err) {
        if (!(err instanceof LockerError) || err.code !== 'E_DECRYPT') throw err;
      } finally {
        kek.fill(0);
      }
    }
    throw new LockerError('Wrong passphrase.', 'E_BAD_PASSPHRASE');
  }

  async saveManifest(): Promise<void> {
    this.file.manifest = sealJson(subkey(this.vdk, 'manifest'), this.manifest, aad(this.id, 'manifest'));
    await this.writeFile();
  }

  async readProfile<T = unknown>(id: string): Promise<T> {
    const raw = await readIfExists(this.paths.profile(id));
    if (raw === null) {
      throw new LockerError(`Profile data for ${id} is missing from the vault.`, 'E_MISSING');
    }
    return openJson<T>(subkey(this.vdk, 'profile', id), JSON.parse(raw) as Sealed, aad(this.id, 'profile', id));
  }

  async writeProfile(id: string, snapshot: unknown): Promise<void> {
    const sealed = sealJson(subkey(this.vdk, 'profile', id), snapshot, aad(this.id, 'profile', id));
    await atomicWrite(this.paths.profile(id), JSON.stringify(sealed));
  }

  async deleteProfile(id: string): Promise<void> {
    await removeIfExists(this.paths.profile(id));
  }

  async writeRollback(record: RollbackRecord): Promise<void> {
    const sealed = sealJson(subkey(this.vdk, 'rollback'), record, aad(this.id, 'rollback'));
    await atomicWrite(this.paths.rollback, JSON.stringify(sealed));
  }

  async readRollback(): Promise<RollbackRecord | null> {
    const raw = await readIfExists(this.paths.rollback);
    if (raw === null) return null;
    return openJson<RollbackRecord>(subkey(this.vdk, 'rollback'), JSON.parse(raw) as Sealed, aad(this.id, 'rollback'));
  }

  async clearRollback(): Promise<void> {
    await removeIfExists(this.paths.rollback);
  }

  /**
   * Change the passphrase AND rotate the data key, so an old vault.json plus a leaked old
   * passphrase can't decrypt anything written afterwards. Crash-safe:
   *   1. stage every blob re-encrypted under the new key as `<file>.rekey`
   *   2. commit by atomically writing vault.json with the new wrapped key
   *   3. promote staged files (also done by finishRekey() on the next unlock if we crash)
   */
  async changePassphrase(next: string): Promise<{ osUnlockRefreshed: boolean }> {
    checkPassphrase(next);
    const newVdk = crypto.randomBytes(32);
    for (const p of this.manifest.profiles) {
      const data = await this.readProfile(p.id);
      const sealed = sealJson(subkey(newVdk, 'profile', p.id), data, aad(this.id, 'profile', p.id));
      await atomicWrite(this.paths.profile(p.id) + REKEY, JSON.stringify(sealed));
    }
    const rollback = await this.readRollback();
    if (rollback) {
      const sealed = sealJson(subkey(newVdk, 'rollback'), rollback, aad(this.id, 'rollback'));
      await atomicWrite(this.paths.rollback + REKEY, JSON.stringify(sealed));
    }

    const kdf = defaultKdf();
    const kek = await deriveKek(next, kdf);
    try {
      this.file.kdf = kdf;
      this.file.wrappedVdk = seal(kek, newVdk, aad(this.id, 'vdk'));
      this.file.manifest = sealJson(subkey(newVdk, 'manifest'), this.manifest, aad(this.id, 'manifest'));
    } finally {
      kek.fill(0);
    }
    await this.writeFile(); // commit point
    this.vdk.fill(0);
    this.vdk = newVdk;
    await this.finishRekey();

    // The OS cache still holds the old key; replace it (or turn OS unlock off if that fails).
    if (!this.file.osUnlock) return { osUnlockRefreshed: false };
    try {
      await this.enableOsUnlock();
      return { osUnlockRefreshed: true };
    } catch {
      await this.disableOsUnlock().catch(() => undefined);
      return { osUnlockRefreshed: false };
    }
  }

  /**
   * Complete or discard a re-key interrupted by a crash: a staged file that opens with the
   * current key was committed and replaces the old file; one that doesn't is discarded.
   */
  private async finishRekey(): Promise<void> {
    const staged: { file: string; key: Buffer; ad: string }[] = [];
    if (fs.existsSync(this.paths.rollback + REKEY)) {
      staged.push({ file: this.paths.rollback, key: subkey(this.vdk, 'rollback'), ad: aad(this.id, 'rollback') });
    }
    for (const name of fs.existsSync(this.paths.profilesDir) ? fs.readdirSync(this.paths.profilesDir) : []) {
      const m = name.match(/^(.+)\.enc\.rekey$/);
      if (!m?.[1]) continue;
      const id = m[1];
      staged.push({ file: this.paths.profile(id), key: subkey(this.vdk, 'profile', id), ad: aad(this.id, 'profile', id) });
    }
    for (const s of staged) {
      const tmp = s.file + REKEY;
      try {
        open(s.key, JSON.parse(fs.readFileSync(tmp, 'utf8')) as Sealed, s.ad).fill(0);
        await fs.promises.rename(tmp, s.file);
      } catch {
        await removeIfExists(tmp);
      }
    }
  }

  async enableOsUnlock(): Promise<string> {
    const cache = Vault.osCache(this.paths);
    if (!cache) {
      throw new LockerError(
        'This platform has no supported OS key store; the passphrase will be required each time.',
        'E_OS_UNLOCK_UNSUPPORTED',
      );
    }
    await cache.store(this.id, this.vdk);
    const roundTrip = await cache.load(this.id);
    if (!roundTrip || !roundTrip.equals(this.vdk)) {
      await cache.clear(this.id);
      throw new LockerError(`${cache.name} did not return the stored key.`, 'E_OS_UNLOCK');
    }
    roundTrip.fill(0);
    this.file.osUnlock = true;
    await this.writeFile();
    return cache.name;
  }

  async disableOsUnlock(): Promise<void> {
    const cache = Vault.osCache(this.paths);
    if (cache) await cache.clear(this.id);
    this.file.osUnlock = false;
    await this.writeFile();
  }

  async audit(event: string): Promise<void> {
    const line = `${new Date().toISOString()} ${event}\n`;
    await fs.promises.appendFile(this.paths.audit, line, { mode: 0o600 });
  }

  /** Zero the in-memory data key. The instance is unusable afterwards. */
  close(): void {
    this.vdk.fill(0);
  }

  private async writeFile(): Promise<void> {
    await atomicWrite(this.paths.vault, JSON.stringify(this.file, null, 2) + '\n');
  }
}

export function checkPassphrase(pass: string): void {
  if ([...pass].length < MIN_PASSPHRASE_LENGTH) {
    throw new LockerError(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`, 'E_WEAK_PASSPHRASE');
  }
}

function parseVaultFile(raw: string): VaultFile {
  let parsed: Partial<VaultFile>;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new LockerError('vault.json is not valid JSON.', 'E_FORMAT');
  }
  if ((parsed.format !== 'agyhub-vault' && parsed.format !== 'ai-locker-vault') || parsed.schema !== 1 || !parsed.vaultId || !parsed.kdf || !parsed.wrappedVdk || !parsed.manifest) {
    throw new LockerError('vault.json has an unsupported format or schema version.', 'E_FORMAT');
  }
  return parsed as VaultFile;
}

function normalizeManifest(m: Partial<Manifest>): Manifest {
  return { profiles: m.profiles ?? [], active: m.active ?? {}, lastActive: m.lastActive ?? {} };
}
