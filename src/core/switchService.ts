import { LockerError } from '../util/errors.js';
import type { Identity, LoginOptions, Provider, VerifyResult } from '../providers/Provider.js';
import type { ProfileMeta, Vault } from '../vault/vault.js';
import { applyIdentity, assertNameFree, describeProfile, matchProfile, newProfileMeta } from './profiles.js';

export interface Ctx {
  vault: Vault;
  provider: Provider<any>;
}

/** What to do when the live login is not in the vault yet. */
export interface UnknownLivePolicy {
  /** Save it under this name without asking. */
  saveUnknownAs?: string;
  /** Overwrite it without saving. */
  discardLive?: boolean;
  /** Interactive fallback: return a name to save under, or null to abort. */
  onUnknown?: (identity: Identity) => Promise<string | null>;
}

export interface GuardOptions extends UnknownLivePolicy {
  /** Proceed even if the provider is running. */
  force?: boolean;
  /** Confirm the result with the provider's own CLI (default true). */
  verify?: boolean;
}

export type CaptureResult =
  | { kind: 'empty' }
  | { kind: 'unchanged' | 'updated' | 'saved-new'; profile: ProfileMeta }
  | { kind: 'discarded'; identity: Identity };

export async function ensureNotRunning(provider: Provider<any>, force?: boolean): Promise<void> {
  if (force) return;
  const procs = await provider.runningProcesses();
  if (procs.length > 0) {
    const list = procs.map((p) => `${p.name} (pid ${p.pid})`).join(', ');
    throw new LockerError(
      `${provider.displayName} is running: ${list}.`,
      'E_RUNNING',
      `Quit every ${provider.displayName} session so it can't write old tokens back, then retry. Use --force to skip this check.`,
    );
  }
}

/**
 * An interrupted operation left the previous login only in the rollback record. Starting a
 * new operation would overwrite that record, so require `ai-locker rollback` first.
 */
async function assertNoPendingRollback(vault: Vault): Promise<void> {
  const pending = await vault.readRollback();
  if (pending) {
    throw new LockerError(
      `A previous operation ("${pending.reason}", ${pending.takenAt}) was interrupted.`,
      'E_PENDING_ROLLBACK',
      'Run `agyhub rollback` to restore the login saved before it, then retry.',
    );
  }
}

/**
 * Save the live login back into the vault. Tokens rotate while the provider runs, so this
 * must happen before anything overwrites the live store, or the saved copy goes stale.
 */
export async function captureLive(ctx: Ctx, policy: UnknownLivePolicy = {}): Promise<CaptureResult> {
  const { vault, provider } = ctx;
  const live = await provider.readLive();
  if (!live || !provider.hasLogin(live)) return { kind: 'empty' };

  const fp = provider.fingerprint(live);
  const identity = provider.identity(live);
  const existing = matchProfile(vault.manifest, provider.id, fp, identity);
  if (existing) {
    const changed = existing.fingerprint !== fp;
    await vault.writeProfile(existing.id, live);
    applyIdentity(existing, fp, identity);
    await vault.saveManifest();
    return { kind: changed ? 'updated' : 'unchanged', profile: existing };
  }

  let name = policy.saveUnknownAs;
  if (!name && !policy.discardLive && policy.onUnknown) {
    name = (await policy.onUnknown(identity)) ?? undefined;
  }
  if (name) {
    assertNameFree(vault.manifest, provider.id, name);
    const meta = newProfileMeta(name, provider.id, fp, identity);
    await vault.writeProfile(meta.id, live);
    vault.manifest.profiles.push(meta);
    vault.manifest.active[provider.id] = meta.id;
    await vault.saveManifest();
    await vault.audit(`save ${provider.id} ${meta.id}`);
    return { kind: 'saved-new', profile: meta };
  }
  if (policy.discardLive) return { kind: 'discarded', identity };

  throw new LockerError(
    `The current ${provider.displayName} login${identity.email ? ` (${identity.email})` : ''} is not saved in the vault.`,
    'E_UNSAVED_LIVE',
    'Re-run with --save-live-as <name> to keep it, or --discard-live to overwrite it.',
  );
}

async function snapshotForRollback(ctx: Ctx, reason: string): Promise<unknown | null> {
  const live = await ctx.provider.readLive();
  await ctx.vault.writeRollback({ provider: ctx.provider.id, takenAt: new Date().toISOString(), reason, snapshot: live });
  return live;
}

async function restoreLive(ctx: Ctx, previous: unknown | null): Promise<void> {
  if (previous === null) await ctx.provider.clearLive();
  else await ctx.provider.writeLive(previous);
}

export interface SwitchResult {
  profile: ProfileMeta;
  capture: CaptureResult;
  verify?: VerifyResult;
  alreadyActive: boolean;
}

export async function switchTo(ctx: Ctx, target: ProfileMeta, opts: GuardOptions = {}): Promise<SwitchResult> {
  const { vault, provider } = ctx;
  await assertNoPendingRollback(vault);
  await ensureNotRunning(provider, opts.force);

  const capture = await captureLive(ctx, opts);
  const alreadyActive = 'profile' in capture && capture.profile.id === target.id;

  let verify: VerifyResult | undefined;
  if (!alreadyActive) {
    const previous = await snapshotForRollback(ctx, `use ${target.name}`);
    try {
      await provider.writeLive(await vault.readProfile(target.id));
      if (opts.verify !== false) {
        verify = await provider.verifyLive(target);
        if (!verify.ok) throw new LockerError(`Verification failed: ${verify.detail}`, 'E_VERIFY');
      }
    } catch (err) {
      await restoreLive(ctx, previous);
      await vault.clearRollback();
      await vault.audit(`use ${provider.id} ${target.id} failed-restored`);
      throw err;
    }
    await vault.clearRollback();
  }

  vault.manifest.active[provider.id] = target.id;
  target.lastUsedAt = new Date().toISOString();
  await vault.saveManifest();
  await vault.audit(`use ${provider.id} ${target.id} ok`);
  return { profile: target, capture, verify, alreadyActive };
}

export interface AddOptions extends GuardOptions {
  login?: LoginOptions;
  /** Instead of spawning the login, wait for the user to log in themselves. */
  manual?: () => Promise<void>;
}

export interface AddResult {
  profile: ProfileMeta;
  capture: CaptureResult;
  /** The account was already in the vault under another name; that profile was refreshed. */
  duplicateOf?: ProfileMeta;
  verify?: VerifyResult;
}

/**
 * Log in to a new account without ever calling logout: save the current login, empty the
 * live store, let the provider's own login flow fill it, then encrypt what it wrote.
 */
export async function addViaLogin(ctx: Ctx, name: string, opts: AddOptions = {}): Promise<AddResult> {
  const { vault, provider } = ctx;
  assertNameFree(vault.manifest, provider.id, name);
  await assertNoPendingRollback(vault);
  await ensureNotRunning(provider, opts.force);

  const capture = await captureLive(ctx, opts);
  const previous = await snapshotForRollback(ctx, `add ${name}`);
  let created: ProfileMeta | undefined;
  try {
    await provider.clearLive();
    if (opts.manual) {
      await opts.manual();
    } else {
      const code = await provider.login(opts.login ?? {});
      if (code !== 0) throw new LockerError(`Login exited with code ${code}.`, 'E_LOGIN');
    }
    const live = await provider.readLive();
    if (!live || !provider.hasLogin(live)) {
      throw new LockerError('No login was found after the login step finished.', 'E_LOGIN');
    }
    const fp = provider.fingerprint(live);
    const identity = provider.identity(live);
    const dup = matchProfile(vault.manifest, provider.id, fp, identity);
    let profile: ProfileMeta;
    if (dup) {
      applyIdentity(dup, fp, identity);
      await vault.writeProfile(dup.id, live);
      profile = dup;
    } else {
      profile = created = newProfileMeta(name, provider.id, fp, identity);
      await vault.writeProfile(profile.id, live);
      vault.manifest.profiles.push(profile);
    }
    let verify: VerifyResult | undefined;
    if (opts.verify !== false) {
      verify = await provider.verifyLive(identity);
      if (!verify.ok) throw new LockerError(`Verification failed: ${verify.detail}`, 'E_VERIFY');
    }
    vault.manifest.active[provider.id] = profile.id;
    profile.lastUsedAt = new Date().toISOString();
    await vault.saveManifest();
    await vault.clearRollback();
    await vault.audit(`add ${provider.id} ${profile.id}${dup ? ' duplicate' : ''}`);
    return { profile, capture, duplicateOf: dup, verify };
  } catch (err) {
    await restoreLive(ctx, previous);
    if (created) {
      const id = created.id;
      vault.manifest.profiles = vault.manifest.profiles.filter((p) => p.id !== id);
      await vault.deleteProfile(id);
    }
    await vault.clearRollback();
    await vault.audit(`add ${provider.id} failed-restored`);
    throw err;
  }
}

/** Save whatever is logged in right now under a new name. */
export async function addFromLive(ctx: Ctx, name: string): Promise<ProfileMeta> {
  const { vault, provider } = ctx;
  assertNameFree(vault.manifest, provider.id, name);
  const live = await provider.readLive();
  if (!live || !provider.hasLogin(live)) {
    throw new LockerError(`${provider.displayName} is not logged in.`, 'E_NO_LIVE', 'Log in first, or use `agyhub add <name>`.');
  }
  const fp = provider.fingerprint(live);
  const identity = provider.identity(live);
  const existing = matchProfile(vault.manifest, provider.id, fp, identity);
  if (existing) {
    await vault.writeProfile(existing.id, live);
    applyIdentity(existing, fp, identity);
    await vault.saveManifest();
    throw new LockerError(
      `This login is already saved as "${existing.name}" (refreshed it).`,
      'E_EXISTS',
      `Rename it with \`agyhub rename ${existing.name} ${name}\` if you prefer the new name.`,
    );
  }
  const meta = newProfileMeta(name, provider.id, fp, identity);
  await vault.writeProfile(meta.id, live);
  vault.manifest.profiles.push(meta);
  vault.manifest.active[provider.id] = meta.id;
  await vault.saveManifest();
  await vault.audit(`add ${provider.id} ${meta.id} from-live`);
  return meta;
}

/** Move the live login into the vault and leave the provider logged out. */
export async function lockLive(ctx: Ctx, opts: GuardOptions = {}): Promise<CaptureResult> {
  const { vault, provider } = ctx;
  await assertNoPendingRollback(vault);
  await ensureNotRunning(provider, opts.force);
  const capture = await captureLive(ctx, opts);
  if (capture.kind === 'empty') return capture;
  const previous = await snapshotForRollback(ctx, 'lock');
  try {
    await provider.clearLive();
  } catch (err) {
    await restoreLive(ctx, previous);
    throw err;
  }
  await vault.clearRollback();
  vault.manifest.lastActive[provider.id] = vault.manifest.active[provider.id] ?? null;
  vault.manifest.active[provider.id] = null;
  await vault.saveManifest();
  await vault.audit(`lock ${provider.id}`);
  return capture;
}

/** Restore the live store from an interrupted operation's rollback record. */
export async function rollback(ctx: Ctx, opts: { force?: boolean } = {}): Promise<{ takenAt: string; reason: string } | null> {
  const record = await ctx.vault.readRollback();
  if (!record || record.provider !== ctx.provider.id) return null;
  await ensureNotRunning(ctx.provider, opts.force);
  await restoreLive(ctx, record.snapshot);
  await ctx.vault.clearRollback();
  await ctx.vault.audit(`rollback ${ctx.provider.id}`);
  return { takenAt: record.takenAt, reason: record.reason };
}

export function captureSummary(c: CaptureResult): string | null {
  switch (c.kind) {
    case 'updated':
      return `Saved refreshed tokens for ${describeProfile(c.profile)}.`;
    case 'saved-new':
      return `Saved the previous login as ${describeProfile(c.profile)}.`;
    case 'discarded':
      return `Discarded the unsaved previous login${c.identity.email ? ` (${c.identity.email})` : ''}.`;
    default:
      return null;
  }
}
