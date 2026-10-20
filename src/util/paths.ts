import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Root of AGYHub's own state. Override with AGYHUB_HOME or AI_LOCKER_HOME (used by tests). */
export function lockerHome(env: NodeJS.ProcessEnv = process.env): string {
  if (env.AGYHUB_HOME) return env.AGYHUB_HOME;
  if (env.AI_LOCKER_HOME) return env.AI_LOCKER_HOME;
  const agyHome = path.join(os.homedir(), '.agyhub');
  const legacyHome = path.join(os.homedir(), '.ai-locker');
  if (fs.existsSync(legacyHome) && !fs.existsSync(agyHome)) {
    return legacyHome;
  }
  return agyHome;
}

export function lockerPaths(home = lockerHome()) {
  return {
    home,
    vault: path.join(home, 'vault.json'),
    profilesDir: path.join(home, 'profiles'),
    profile: (id: string) => path.join(home, 'profiles', `${id}.enc`),
    rollback: path.join(home, 'rollback.enc'),
    osUnlockBlob: path.join(home, 'os-unlock.bin'),
    audit: path.join(home, 'audit.log'),
    lock: path.join(home, '.lock'),
  };
}

export type LockerPaths = ReturnType<typeof lockerPaths>;
