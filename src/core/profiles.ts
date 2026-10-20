import { LockerError } from '../util/errors.js';
import { randomId } from '../vault/crypto.js';
import type { Manifest, ProfileMeta } from '../vault/vault.js';
import type { Identity } from '../providers/Provider.js';

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function validateName(name: string): string {
  if (!NAME_RE.test(name)) {
    throw new LockerError(
      `Invalid profile name "${name}".`,
      'E_ARGS',
      'Use 1-64 characters: letters, digits, ".", "_" or "-", starting with a letter or digit.',
    );
  }
  return name;
}

export function findProfile(manifest: Manifest, provider: string, ref: string): ProfileMeta | undefined {
  const list = manifest.profiles.filter((p) => p.provider === provider);
  const lower = ref.toLowerCase();
  return (
    list.find((p) => p.name.toLowerCase() === lower) ??
    list.find((p) => p.email?.toLowerCase() === lower) ??
    (ref.length >= 6 ? list.find((p) => p.id.startsWith(lower)) : undefined)
  );
}

export function requireProfile(manifest: Manifest, provider: string, ref: string): ProfileMeta {
  const p = findProfile(manifest, provider, ref);
  if (!p) {
    throw new LockerError(`No profile named "${ref}".`, 'E_NOT_FOUND', 'Run `agyhub list` to see saved profiles.');
  }
  return p;
}

export function assertNameFree(manifest: Manifest, provider: string, name: string): void {
  validateName(name);
  if (manifest.profiles.some((p) => p.provider === provider && p.name.toLowerCase() === name.toLowerCase())) {
    throw new LockerError(`A profile named "${name}" already exists.`, 'E_EXISTS');
  }
}

/** Find the saved profile a live login belongs to: exact token match first, then same account. */
export function matchProfile(
  manifest: Manifest,
  provider: string,
  fingerprint: string,
  identity: Identity,
): ProfileMeta | undefined {
  const list = manifest.profiles.filter((p) => p.provider === provider);
  return (
    list.find((p) => p.fingerprint === fingerprint) ??
    (identity.accountKey ? list.find((p) => p.accountKey === identity.accountKey) : undefined)
  );
}

export function newProfileMeta(name: string, provider: string, fingerprint: string, identity: Identity): ProfileMeta {
  const now = new Date().toISOString();
  return {
    id: randomId(16),
    name,
    provider,
    fingerprint,
    createdAt: now,
    updatedAt: now,
    ...identityFields(identity),
  };
}

export function applyIdentity(meta: ProfileMeta, fingerprint: string, identity: Identity): void {
  Object.assign(meta, identityFields(identity), { fingerprint, updatedAt: new Date().toISOString() });
}

function identityFields(identity: Identity): Partial<ProfileMeta> {
  const out: Partial<ProfileMeta> = {};
  // Keep previously known values if the live login lacks them (e.g. oauthAccount not fetched yet).
  if (identity.accountKey) out.accountKey = identity.accountKey;
  if (identity.email) out.email = identity.email;
  if (identity.organization) out.organization = identity.organization;
  if (identity.plan) out.plan = identity.plan;
  if (identity.tokenExpiresAt) out.tokenExpiresAt = identity.tokenExpiresAt;
  if (identity.refreshExpiresAt) out.refreshExpiresAt = identity.refreshExpiresAt;
  return out;
}

export function describeProfile(p: Pick<ProfileMeta, 'name' | 'email' | 'organization' | 'plan'>): string {
  const extras = [p.email, p.plan, p.organization && p.organization !== p.email ? p.organization : undefined].filter(
    Boolean,
  );
  return extras.length ? `${p.name} (${extras.join(', ')})` : p.name;
}
