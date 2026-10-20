import fs from 'node:fs';
import type { Command } from 'commander';
import { c, emit, info, relTime } from '../../util/output.js';
import { lockerPaths } from '../../util/paths.js';
import { describeDirAccess } from '../../vault/perms.js';
import { hasArgon2 } from '../../vault/crypto.js';
import { Vault } from '../../vault/vault.js';
import { describeProfile, matchProfile } from '../../core/profiles.js';
import { getProvider } from '../../providers/index.js';
import type { DoctorCheck, UsageReport } from '../../providers/Provider.js';
import { withVault, type GlobalOpts } from '../context.js';
import { publicMeta } from './profiles.js';

export function registerInspect(program: Command): void {
  program
    .command('status')
    .description('show the active profile and the live login')
    .option('-u, --usage', 'fetch usage if supported by the provider')
    .action(async (opts: { usage?: boolean }, cmd: Command) => {
      const g = cmd.optsWithGlobals<GlobalOpts>();
      await withVault(g, async ({ vault, provider }) => {
        const activeId = vault.manifest.active[provider.id] ?? null;
        const active = vault.manifest.profiles.find((p) => p.id === activeId) ?? null;
        const live = await provider.readLive();
        const liveLogin = live && provider.hasLogin(live) ? live : null;
        const liveId = liveLogin ? provider.identity(liveLogin) : null;
        const liveMatch = liveLogin
          ? matchProfile(vault.manifest, provider.id, provider.fingerprint(liveLogin), liveId ?? {})
          : undefined;

        const usage: Record<string, UsageReport> = {};
        if (opts.usage && provider.usage) {
          for (const p of vault.manifest.profiles.filter((x) => x.provider === provider.id)) {
            // The live store holds the freshest tokens for whichever profile it belongs to.
            const snap = liveMatch?.id === p.id && liveLogin ? liveLogin : await vault.readProfile(p.id);
            usage[p.name] = await provider.usage(snap);
          }
        }

        const data = {
          provider: provider.id,
          store: provider.describeStore(),
          active: active ? publicMeta(active, activeId) : null,
          live: liveId
            ? {
                email: liveId.email ?? null,
                plan: liveId.plan ?? null,
                savedAs: liveMatch?.name ?? null,
                tokenExpiresAt: liveId.tokenExpiresAt ?? null,
                refreshExpiresAt: liveId.refreshExpiresAt ?? null,
              }
            : null,
          usage: opts.usage ? usage : undefined,
        };

        emit(g, data, () => {
          info(`${c.bold('Active profile')}  ${active ? describeProfile(active) : c.dim('none')}`);
          if (liveId) {
            const saved = liveMatch ? c.green(`saved as "${liveMatch.name}"`) : c.yellow('NOT saved in the vault');
            info(`${c.bold('Live login')}      ${liveId.email ?? 'unknown email'} (${liveId.plan ?? '?'}) — ${saved}`);
            if (liveId.tokenExpiresAt) {
              info(`${c.bold('Access token')}    expires ${relTime(liveId.tokenExpiresAt)}`);
            }
            if (liveId.refreshExpiresAt) {
              info(`${c.bold('Login')}           expires ${relTime(liveId.refreshExpiresAt)}`);
            }
          } else {
            info(`${c.bold('Live login')}      ${c.dim('none (logged out)')}`);
          }
          info(`${c.bold('Store')}           ${data.store.kind}: ${data.store.location}`);
          if (opts.usage && Object.keys(usage).length > 0) {
            info('');
            for (const [name, report] of Object.entries(usage)) {
              if (!report.ok) {
                info(`${c.bold(name)}: ${c.dim(report.error ?? 'unavailable')}`);
                continue;
              }
              const parts = report.windows.map(
                (w) =>
                  `${w.label} ${w.percent === null ? '?' : `${Math.round(w.percent)}%`}` +
                  (w.resetsAt ? c.dim(` (resets ${relTime(Date.parse(w.resetsAt))})`) : ''),
              );
              info(`${c.bold(name)}: ${parts.join(' · ') || c.dim('no limits reported')}`);
            }
          }
        });
      });
    });

  program
    .command('doctor')
    .description('diagnose the vault, permissions and setup')
    .action(async (_opts, cmd: Command) => {
      const g = cmd.optsWithGlobals<GlobalOpts>();
      const paths = lockerPaths();
      const checks: DoctorCheck[] = [];
      checks.push({ name: 'Node.js', status: 'info', detail: `${process.version} (${hasArgon2 ? 'Argon2id available' : 'scrypt only'})` });
      checks.push({ name: 'Platform', status: 'info', detail: `${process.platform} ${process.arch}` });

      if (!Vault.exists(paths)) {
        checks.push({ name: 'Vault', status: 'warn', detail: `none at ${paths.home}; run \`agyhub init\`` });
      } else {
        checks.push({ name: 'Vault', status: 'ok', detail: paths.home });
        const access = describeDirAccess(paths.home);
        checks.push({
          name: 'Vault permissions',
          status: access.ok ? 'ok' : 'warn',
          detail: access.ok ? access.detail : `others may have access: ${access.detail}`,
        });
        if (fs.existsSync(paths.rollback)) {
          checks.push({
            name: 'Interrupted operation',
            status: 'warn',
            detail: 'a rollback snapshot exists; run `agyhub rollback` to restore the login from before it',
          });
        }
        try {
          await withVault(g, async ({ vault, provider }) => {
            checks.push({
              name: 'Unlock',
              status: 'ok',
              detail: `via ${vault.unlockedVia}; OS unlock ${vault.osUnlockEnabled ? 'on' : 'off'}; ${vault.manifest.profiles.length} profile(s)`,
            });
            for (const p of vault.manifest.profiles.filter((x) => x.provider === provider.id)) {
              if (p.refreshExpiresAt && p.refreshExpiresAt < Date.now()) {
                checks.push({ name: `Profile ${p.name}`, status: 'warn', detail: 'login expired; re-add it with `agyhub add`' });
              } else if (p.refreshExpiresAt && p.refreshExpiresAt - Date.now() < 3 * 86_400_000) {
                checks.push({ name: `Profile ${p.name}`, status: 'warn', detail: `login expires ${relTime(p.refreshExpiresAt)}` });
              }
            }
          });
        } catch (err) {
          checks.push({ name: 'Unlock', status: 'fail', detail: (err as Error).message });
        }
      }

      const provider = getProvider();
      checks.push(...(await provider.doctor()));
      const procs = await provider.runningProcesses().catch(() => []);
      checks.push({
        name: 'Running sessions',
        status: procs.length ? 'info' : 'ok',
        detail: procs.length
          ? `${procs.map((p) => `${p.name}#${p.pid}`).join(', ')} (quit them before switching)`
          : 'none',
      });

      emit(g, { checks }, () => {
        const icon = { ok: c.green('✔'), warn: c.yellow('!'), fail: c.red('✖'), info: c.dim('•') } as const;
        for (const ch of checks) info(`${icon[ch.status]} ${ch.name.padEnd(22)} ${ch.detail}`);
      });
      if (checks.some((ch) => ch.status === 'fail')) process.exitCode = 1;
    });
}
