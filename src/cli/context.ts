import { confirm, input, password } from '@inquirer/prompts';
import { LockerError } from '../util/errors.js';
import { lockerPaths } from '../util/paths.js';
import { withLock } from '../vault/lock.js';
import { Vault } from '../vault/vault.js';
import { getProvider } from '../providers/index.js';
import type { Ctx, UnknownLivePolicy } from '../core/switchService.js';
import type { Identity } from '../providers/Provider.js';
import { note } from '../util/output.js';

export interface GlobalOpts {
  json?: boolean;
  strict?: boolean;
}

export const isInteractive = () => Boolean(process.stdin.isTTY && process.stdout.isTTY) && !process.env.CI;

export async function promptPassphrase(message = 'Vault passphrase'): Promise<string> {
  return password({ message, mask: '*' });
}

async function getPassphrase(attempt: number): Promise<string | null> {
  const fromEnv = process.env.AGYHUB_PASSPHRASE ?? process.env.AI_LOCKER_PASSPHRASE;
  if (fromEnv !== undefined) {
    if (attempt > 1) throw new LockerError('Passphrase from environment is incorrect.', 'E_BAD_PASSPHRASE');
    return fromEnv;
  }
  if (!isInteractive()) {
    throw new LockerError(
      'The vault passphrase is required but there is no terminal to ask for it.',
      'E_NEED_PASSPHRASE',
      'Set AGYHUB_PASSPHRASE, or enable OS unlock with `agyhub config os-unlock on`.',
    );
  }
  if (attempt > 1) note('Wrong passphrase, try again.');
  return promptPassphrase();
}

/** Open the vault under the cross-process lock, run `fn`, then wipe the key from memory. */
export async function withVault<T>(g: GlobalOpts, fn: (ctx: Ctx) => Promise<T>): Promise<T> {
  const paths = lockerPaths();
  if (!Vault.exists(paths)) {
    throw new LockerError('No vault found.', 'E_NO_VAULT', 'Run `agyhub init` to create one.');
  }
  return withLock(paths.lock, async () => {
    const vault = await Vault.unlock(paths, { strict: g.strict, getPassphrase });
    try {
      return await fn({ vault, provider: getProvider() });
    } finally {
      vault.close();
    }
  });
}

export interface LivePolicyFlags {
  saveLiveAs?: string;
  discardLive?: boolean;
}

/** Build the "current login isn't saved" policy from flags, asking interactively if allowed. */
export function livePolicy(flags: LivePolicyFlags): UnknownLivePolicy {
  return {
    saveUnknownAs: flags.saveLiveAs,
    discardLive: flags.discardLive,
    onUnknown: isInteractive() ? askToSaveUnknown : undefined,
  };
}

async function askToSaveUnknown(identity: Identity): Promise<string | null> {
  const who = identity.email ? ` (${identity.email})` : '';
  const save = await confirm({ message: `The current login${who} is not in the vault. Save it first?`, default: true });
  if (!save) return null;
  return input({
    message: 'Name for this profile',
    default: suggestName(identity.email),
    validate: (v) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(v) || 'Letters, digits, ".", "_" or "-" only',
  });
}

export function suggestName(email?: string): string {
  const local = email?.split('@')[0]?.replace(/[^A-Za-z0-9._-]/g, '') ?? '';
  return /^[A-Za-z0-9]/.test(local) ? local.slice(0, 64) : 'previous';
}
