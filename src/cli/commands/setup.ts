import type { Command } from 'commander';
import { confirm } from '@inquirer/prompts';
import { LockerError } from '../../util/errors.js';
import { lockerPaths } from '../../util/paths.js';
import { c, emit, info, note, warn } from '../../util/output.js';
import { defaultKdf, hasArgon2 } from '../../vault/crypto.js';
import { checkPassphrase, MIN_PASSPHRASE_LENGTH, Vault } from '../../vault/vault.js';
import { isInteractive, promptPassphrase, withVault, type GlobalOpts } from '../context.js';

async function newPassphrase(label = 'New vault passphrase'): Promise<string> {
  const fromEnv =
    process.env.AGYHUB_NEW_PASSPHRASE ??
    process.env.AI_LOCKER_NEW_PASSPHRASE ??
    process.env.AGYHUB_PASSPHRASE ??
    process.env.AI_LOCKER_PASSPHRASE;
  if (fromEnv !== undefined && !isInteractive()) {
    checkPassphrase(fromEnv);
    return fromEnv;
  }
  if (!isInteractive()) {
    throw new LockerError('A passphrase is required.', 'E_NEED_PASSPHRASE', 'Set AGYHUB_PASSPHRASE or run in a terminal.');
  }
  for (;;) {
    const first = await promptPassphrase(`${label} (min ${MIN_PASSPHRASE_LENGTH} chars)`);
    try {
      checkPassphrase(first);
    } catch (err) {
      note(c.red((err as Error).message));
      continue;
    }
    const second = await promptPassphrase('Repeat passphrase');
    if (first === second) return first;
    note(c.red('Passphrases did not match.'));
  }
}

export function registerSetup(program: Command): void {
  program
    .command('init')
    .description('create the encrypted vault (~/.agyhub)')
    .option('--no-os-unlock', 'always ask for the passphrase; do not cache the vault key in the OS key store')
    .option('--scrypt', 'use scrypt instead of Argon2id (for vaults shared with Node < 24.7)')
    .action(async (opts: { osUnlock: boolean; scrypt?: boolean }, cmd: Command) => {
      const g = cmd.optsWithGlobals<GlobalOpts>();
      const paths = lockerPaths();
      if (Vault.exists(paths)) throw new LockerError(`A vault already exists at ${paths.home}.`, 'E_EXISTS');
      if (!isInteractive() && !g.json) note('Creating vault non-interactively.');
      note(c.bold('Choose a vault passphrase.') + ' It encrypts every saved login; it cannot be recovered if lost.');
      const pass = await newPassphrase();
      const kdf = defaultKdf(Boolean(opts.scrypt));
      const { vault, hardened, osUnlockError } = await Vault.create(paths, pass, {
        osUnlock: opts.osUnlock && !g.strict,
        kdf,
      });
      vault.close();
      if (!hardened) warn(`Could not restrict permissions on ${paths.home}. Check its access rights manually.`);
      if (osUnlockError) warn(`OS unlock was not enabled: ${osUnlockError}`);
      emit(g, { vault: paths.home, kdf: kdf.name, osUnlock: vault.osUnlockEnabled }, () => {
        info(c.green('✔ ') + `Vault created at ${paths.home}`);
        info(`  Key derivation: ${kdf.name}${kdf.name === 'scrypt' && !opts.scrypt && !hasArgon2 ? ' (Argon2id needs Node 24.7+)' : ''}`);
        info(`  OS unlock: ${vault.osUnlockEnabled ? 'on (no passphrase prompt for routine commands)' : 'off'}`);
        info('\nNext: `agyhub add <name> --from-live` to save the account you are logged in with now,');
        info('      or `agyhub add <name>` to log in to another account.');
      });
    });

  program
    .command('passphrase')
    .description('change the vault passphrase')
    .action(async (_opts, cmd: Command) => {
      const g = cmd.optsWithGlobals<GlobalOpts>();
      // Always prove knowledge of the current passphrase, even if OS unlock is on.
      const res = await withVault({ ...g, strict: true }, async ({ vault }) => {
        const osUnlockWasOn = vault.osUnlockEnabled;
        const next = await newPassphrase('New passphrase');
        const out = await vault.changePassphrase(next);
        await vault.audit('passphrase-changed rekeyed');
        return { ...out, osUnlockWasOn };
      });
      emit(g, { ok: true, rekeyed: true, osUnlock: res.osUnlockRefreshed }, () => {
        info(c.green('✔ ') + 'Passphrase changed and the vault data key rotated.');
        if (res.osUnlockWasOn && !res.osUnlockRefreshed) warn('OS unlock could not be refreshed and was turned off.');
      });
    });

  const config = program.command('config').description('view or change vault settings');
  config
    .command('show')
    .description('show vault settings')
    .action(async (_opts, cmd: Command) => {
      const g = cmd.optsWithGlobals<GlobalOpts>();
      await withVault(g, async ({ vault }) => {
        const data = {
          vault: vault.paths.home,
          vaultId: vault.id,
          kdf: vault.kdf.name,
          osUnlock: vault.osUnlockEnabled,
          osKeyStore: Vault.osCache(vault.paths)?.name ?? null,
          unlockedVia: vault.unlockedVia,
        };
        emit(g, data, () => {
          for (const [k, v] of Object.entries(data)) info(`${k.padEnd(12)} ${String(v)}`);
        });
      });
    });
  config
    .command('os-unlock <state>')
    .description('turn the OS-bound key cache on or off (on | off)')
    .action(async (state: string, _opts, cmd: Command) => {
      const g = cmd.optsWithGlobals<GlobalOpts>();
      if (state !== 'on' && state !== 'off') throw new LockerError('State must be "on" or "off".', 'E_ARGS');
      // Enrolling a new OS copy of the key requires the passphrase.
      await withVault({ ...g, strict: state === 'on' ? true : g.strict }, async ({ vault }) => {
        if (state === 'on') {
          const store = await vault.enableOsUnlock();
          await vault.audit('os-unlock on');
          emit(g, { osUnlock: true, store }, () => info(c.green('✔ ') + `OS unlock enabled via ${store}.`));
        } else {
          if (isInteractive() && !g.json) {
            const ok = await confirm({ message: 'Require the passphrase for every command from now on?', default: true });
            if (!ok) return;
          }
          await vault.disableOsUnlock();
          await vault.audit('os-unlock off');
          emit(g, { osUnlock: false }, () => info(c.green('✔ ') + 'OS unlock disabled; the passphrase is now required.'));
        }
      });
    });
}
