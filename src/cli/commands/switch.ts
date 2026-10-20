import type { Command } from 'commander';
import { confirm, select } from '@inquirer/prompts';
import { LockerError } from '../../util/errors.js';
import { c, emit, info, warn } from '../../util/output.js';
import { captureSummary, lockLive, rollback, switchTo } from '../../core/switchService.js';
import { describeProfile, requireProfile } from '../../core/profiles.js';
import { isInteractive, livePolicy, withVault, type GlobalOpts, type LivePolicyFlags } from '../context.js';
import { publicMeta } from './profiles.js';

interface SwitchFlags extends LivePolicyFlags {
  force?: boolean;
  verify: boolean;
}

function switchOptions(cmd: Command): Command {
  return cmd
    .option('--save-live-as <name>', 'if the current login is not saved yet, save it under this name first')
    .option('--discard-live', 'if the current login is not saved yet, drop it')
    .option('--force', 'skip the running process check')
    .option('--no-verify', 'skip login verification');
}

export function registerSwitch(program: Command): void {
  switchOptions(
    program
      .command('use [profile]')
      .alias('switch')
      .description('make a saved profile the active login (picker if omitted)'),
  ).action(async (ref: string | undefined, flags: SwitchFlags, cmd: Command) => {
    const g = cmd.optsWithGlobals<GlobalOpts>();
    await withVault(g, async (ctx) => {
      const { vault, provider } = ctx;
      const profiles = vault.manifest.profiles.filter((p) => p.provider === provider.id);
      if (profiles.length === 0) throw new LockerError('No profiles saved yet.', 'E_EMPTY', 'Run `agyhub add <name>`.');
      let target;
      if (ref) {
        target = requireProfile(vault.manifest, provider.id, ref);
      } else {
        if (!isInteractive()) throw new LockerError('Specify a profile name.', 'E_ARGS');
        const activeId = vault.manifest.active[provider.id];
        const id = await select({
          message: `Switch ${provider.displayName} to`,
          choices: profiles.map((p) => ({
            name: `${p.id === activeId ? '* ' : '  '}${describeProfile(p)}`,
            value: p.id,
          })),
          default: activeId ?? undefined,
        });
        target = profiles.find((p) => p.id === id)!;
      }

      const res = await switchTo(ctx, target, { ...livePolicy(flags), force: flags.force, verify: flags.verify });
      const pre = captureSummary(res.capture);
      emit(g, { profile: publicMeta(res.profile, res.profile.id), alreadyActive: res.alreadyActive, verified: res.verify ?? null }, () => {
        if (pre) info(c.dim(pre));
        info(
          res.alreadyActive
            ? c.green('✔ ') + `${describeProfile(res.profile)} is already active.`
            : c.green('✔ ') + `Active: ${describeProfile(res.profile)}`,
        );
        if (res.verify?.skipped) warn(res.verify.detail);
      });
    });
  });

  switchOptions(
    program.command('lock').description('move the live login into the vault and leave logged out'),
  ).action(async (flags: SwitchFlags, cmd: Command) => {
    const g = cmd.optsWithGlobals<GlobalOpts>();
    await withVault(g, async (ctx) => {
      const capture = await lockLive(ctx, { ...livePolicy(flags), force: flags.force });
      emit(g, { locked: capture.kind !== 'empty', capture: capture.kind }, () => {
        if (capture.kind === 'empty') {
          info(`${ctx.provider.displayName} is not logged in; nothing to lock.`);
          return;
        }
        const pre = captureSummary(capture);
        if (pre) info(c.dim(pre));
        info(c.green('✔ ') + `Locked. ${ctx.provider.displayName} is logged out; \`agyhub unlock\` restores the last profile.`);
      });
    });
  });

  switchOptions(
    program.command('unlock').description('restore the profile that was active before `lock`'),
  ).action(async (flags: SwitchFlags, cmd: Command) => {
    const g = cmd.optsWithGlobals<GlobalOpts>();
    await withVault(g, async (ctx) => {
      const { vault, provider } = ctx;
      const id = vault.manifest.lastActive[provider.id] ?? vault.manifest.active[provider.id];
      const target = vault.manifest.profiles.find((p) => p.id === id);
      if (!target) {
        throw new LockerError('No previously active profile to restore.', 'E_NOT_FOUND', 'Use `agyhub use <profile>`.');
      }
      const res = await switchTo(ctx, target, { ...livePolicy(flags), force: flags.force, verify: flags.verify });
      vault.manifest.lastActive[provider.id] = null;
      await vault.saveManifest();
      emit(g, { profile: publicMeta(res.profile, res.profile.id) }, () =>
        info(c.green('✔ ') + `Active: ${describeProfile(res.profile)}`),
      );
    });
  });

  program
    .command('rollback')
    .description('restore the login saved before an interrupted switch')
    .option('--force', 'skip the running process check')
    .option('-y, --yes', 'do not ask for confirmation')
    .action(async (opts: { force?: boolean; yes?: boolean }, cmd: Command) => {
      const g = cmd.optsWithGlobals<GlobalOpts>();
      await withVault(g, async (ctx) => {
        const record = await ctx.vault.readRollback();
        if (!record) {
          emit(g, { restored: false }, () => info('No rollback snapshot; the last operation completed normally.'));
          return;
        }
        if (!opts.yes && isInteractive()) {
          const ok = await confirm({
            message: `Restore the ${ctx.provider.displayName} login saved at ${record.takenAt} (before "${record.reason}")?`,
            default: true,
          });
          if (!ok) return;
        }
        const res = await rollback(ctx, { force: opts.force });
        emit(g, { restored: Boolean(res), ...res }, () => info(c.green('✔ ') + 'Restored the previous login.'));
      });
    });
}
