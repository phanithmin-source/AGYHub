import fs from 'node:fs';
import { LockerError, isNodeError } from '../util/errors.js';

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return isNodeError(err) && err.code === 'EPERM';
  }
}

/**
 * Cross-process mutex on the vault: two concurrent ai-locker runs must never interleave
 * captures and writes. A lock is only taken over when its owner process is gone, never on
 * age alone: an interactive `add` may legitimately wait a long time for a browser login.
 */
export async function withLock<T>(lockPath: string, fn: () => Promise<T>): Promise<T> {
  acquire(lockPath);
  try {
    return await fn();
  } finally {
    fs.rmSync(lockPath, { force: true });
  }
}

function acquire(lockPath: string, retried = false): void {
  try {
    const fd = fs.openSync(lockPath, 'wx', 0o600);
    fs.writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }));
    fs.closeSync(fd);
  } catch (err) {
    if (!isNodeError(err) || err.code !== 'EEXIST' || retried) throw err;
    let holder: { pid?: number } = {};
    try {
      holder = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    } catch {
      /* unreadable lock content: owner crashed mid-write, treat as stale */
    }
    if (holder.pid && pidAlive(holder.pid)) {
      throw new LockerError(
        `Another agyhub process (pid ${holder.pid}) is using the vault.`,
        'E_BUSY',
        'Wait for it to finish and try again.',
      );
    }
    fs.rmSync(lockPath, { force: true });
    acquire(lockPath, true);
  }
}
