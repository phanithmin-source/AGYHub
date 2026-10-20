import { LockerError } from '../util/errors.js';
import { checkPassphrase, type ProfileMeta, type Vault } from '../vault/vault.js';
import { defaultKdf, deriveKek, openJson, sealJson, subkey, type KdfParams, type Sealed } from '../vault/crypto.js';
import { matchProfile, newProfileMeta, validateName } from './profiles.js';

interface ExportFile {
  format: 'agyhub-export' | 'ai-locker-export';
  v: 1;
  createdAt: string;
  kdf: KdfParams;
  payload: Sealed;
}

interface ExportPayload {
  profiles: { meta: ProfileMeta; snapshot: unknown }[];
}

const aadFor = (format: string) => `${format}:v1`;

export async function exportProfiles(vault: Vault, profiles: ProfileMeta[], passphrase: string): Promise<string> {
  checkPassphrase(passphrase);
  const payload: ExportPayload = { profiles: [] };
  for (const meta of profiles) {
    payload.profiles.push({ meta, snapshot: await vault.readProfile(meta.id) });
  }
  const kdf = defaultKdf();
  const kek = await deriveKek(passphrase, kdf);
  try {
    const file: ExportFile = {
      format: 'agyhub-export',
      v: 1,
      createdAt: new Date().toISOString(),
      kdf,
      payload: sealJson(subkey(kek, 'export'), payload, aadFor('agyhub-export')),
    };
    return JSON.stringify(file, null, 2) + '\n';
  } finally {
    kek.fill(0);
  }
}

export interface ImportResult {
  imported: ProfileMeta[];
  skipped: { name: string; reason: string }[];
}

export async function importProfiles(vault: Vault, text: string, passphrase: string): Promise<ImportResult> {
  let file: ExportFile;
  try {
    file = JSON.parse(text);
  } catch {
    throw new LockerError('Not an agyhub export file.', 'E_FORMAT');
  }
  if ((file?.format !== 'agyhub-export' && file?.format !== 'ai-locker-export') || file.v !== 1) {
    throw new LockerError('Not an agyhub export file, or an unsupported version.', 'E_FORMAT');
  }
  const kek = await deriveKek(passphrase, file.kdf);
  let payload: ExportPayload;
  try {
    payload = openJson<ExportPayload>(subkey(kek, 'export'), file.payload, aadFor(file.format));
  } catch (err) {
    if (err instanceof LockerError && err.code === 'E_DECRYPT') {
      throw new LockerError('Wrong export passphrase, or the file was modified.', 'E_BAD_PASSPHRASE');
    }
    throw err;
  } finally {
    kek.fill(0);
  }

  const result: ImportResult = { imported: [], skipped: [] };
  for (const { meta, snapshot } of payload.profiles) {
    const existing = matchProfile(vault.manifest, meta.provider, meta.fingerprint, { accountKey: meta.accountKey });
    if (existing) {
      result.skipped.push({ name: safeName(meta.name), reason: `same account as existing profile "${existing.name}"` });
      continue;
    }
    const name = uniqueName(vault, meta.provider, safeName(meta.name));
    const fresh = { ...newProfileMeta(name, meta.provider, meta.fingerprint, {}), ...pickIdentity(meta) };
    await vault.writeProfile(fresh.id, snapshot);
    vault.manifest.profiles.push(fresh);
    result.imported.push(fresh);
  }
  await vault.saveManifest();
  await vault.audit(`import ${result.imported.length}`);
  return result;
}

function pickIdentity(m: ProfileMeta): Partial<ProfileMeta> {
  const { accountKey, email, organization, plan, tokenExpiresAt, refreshExpiresAt } = m;
  return { accountKey, email, organization, plan, tokenExpiresAt, refreshExpiresAt };
}

function safeName(name: unknown): string {
  try {
    return validateName(String(name));
  } catch {
    return 'imported';
  }
}

function uniqueName(vault: Vault, provider: string, base: string): string {
  const taken = new Set(vault.manifest.profiles.filter((p) => p.provider === provider).map((p) => p.name.toLowerCase()));
  if (!taken.has(base.toLowerCase())) return base;
  for (let i = 2; ; i++) {
    const candidate = `${base}-${i}`;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
}
