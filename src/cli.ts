import { Command, CommanderError } from 'commander';
import { LockerError } from './util/errors.js';
import { c } from './util/output.js';
import { registerSetup } from './cli/commands/setup.js';
import { registerProfiles } from './cli/commands/profiles.js';
import { registerSwitch } from './cli/commands/switch.js';
import { registerInspect } from './cli/commands/inspect.js';
import pkg from '../package.json' with { type: 'json' };

const program = new Command();
program
  .name('agyhub')
  .description('AGYHub — Keep several Antigravity (agy) logins in an encrypted vault and switch between them.')
  .version(pkg.version)
  .option('--json', 'machine-readable output (tokens are never printed)')
  .option('--strict', 'ignore the OS key cache and always ask for the passphrase')
  .showHelpAfterError()
  .exitOverride();

registerSetup(program);
registerProfiles(program);
registerSwitch(program);
registerInspect(program);

program.addHelpText(
  'after',
  `
Examples:
  agyhub init                    create the vault
  agyhub add work --from-live    save the account you're logged in with
  agyhub add personal            log in to another account and save it
  agyhub use work                switch Antigravity to "work"
  agyhub status                  active account and token status

Install the agyhub command once with: npm install -g agyhub`,
);

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    process.exitCode = report(err);
  }
}

function report(err: unknown): number {
  const json = process.argv.includes('--json');
  if (err instanceof CommanderError) {
    // Help/version output and argument errors were already printed by commander.
    return err.exitCode;
  }
  if (err instanceof Error && err.name === 'ExitPromptError') {
    process.stderr.write('\nCancelled.\n');
    return 130;
  }
  if (err instanceof LockerError) {
    if (json) {
      process.stdout.write(JSON.stringify({ error: { code: err.code, message: err.message, hint: err.hint ?? null } }, null, 2) + '\n');
    } else {
      process.stderr.write(`${c.red('✖')} ${err.message}\n`);
      if (err.hint) process.stderr.write(`  ${c.dim(err.hint)}\n`);
    }
    return 1;
  }
  const message = err instanceof Error ? err.message : String(err);
  if (json) {
    process.stdout.write(JSON.stringify({ error: { code: 'E_INTERNAL', message } }, null, 2) + '\n');
  } else {
    process.stderr.write(`${c.red('✖')} ${message}\n`);
    const debug = process.env.AGYHUB_DEBUG || process.env.AI_LOCKER_DEBUG;
    if (debug && err instanceof Error) process.stderr.write(`${err.stack}\n`);
  }
  return 1;
}

void main();
