import { run } from '../../util/exec.js';
import { LockerError } from '../../util/errors.js';
import type { OsKeyCache } from './index.js';

/**
 * macOS login Keychain via /usr/bin/security. Writes go through `security -i` with the
 * command on stdin so the key never appears in the process table.
 */
const SECURITY = '/usr/bin/security';
const SERVICE = 'agyhub';
const LEGACY_SERVICE = 'ai-locker';
const ITEM_NOT_FOUND = 44;

function account(vaultId: string): string {
  if (!/^[0-9a-f]+$/i.test(vaultId)) throw new Error('invalid vault id');
  return `vdk-${vaultId}`;
}

export function darwinCache(): OsKeyCache {
  return {
    name: 'macOS Keychain',
    async store(vaultId, vdk) {
      // base64 has no quotes or whitespace, so it is safe inside a quoted -i command line.
      const cmd = `add-generic-password -U -s "${SERVICE}" -a "${account(vaultId)}" -l "agyhub vault key" -w "${vdk.toString('base64')}"\n`;
      const res = await run(SECURITY, ['-i'], { input: cmd, timeoutMs: 30_000 });
      if (res.code !== 0 || /error/i.test(res.stderr)) {
        throw new LockerError('Could not store the vault key in the macOS Keychain.', 'E_OS_UNLOCK', res.stderr.trim());
      }
    },
    async load(vaultId) {
      let res = await run(SECURITY, ['find-generic-password', '-s', SERVICE, '-a', account(vaultId), '-w'], {
        timeoutMs: 60_000,
      });
      if (res.code === ITEM_NOT_FOUND) {
        res = await run(SECURITY, ['find-generic-password', '-s', LEGACY_SERVICE, '-a', account(vaultId), '-w'], {
          timeoutMs: 60_000,
        });
      }
      if (res.code === ITEM_NOT_FOUND) return null;
      if (res.code !== 0) {
        throw new LockerError('Could not read the vault key from the macOS Keychain.', 'E_OS_UNLOCK', res.stderr.trim());
      }
      return Buffer.from(res.stdout.trim(), 'base64');
    },
    async clear(vaultId) {
      for (const s of [SERVICE, LEGACY_SERVICE]) {
        const res = await run(SECURITY, ['delete-generic-password', '-s', s, '-a', account(vaultId)], {
          timeoutMs: 30_000,
        });
        if (res.code !== 0 && res.code !== ITEM_NOT_FOUND) {
          throw new LockerError('Could not remove the vault key from the macOS Keychain.', 'E_OS_UNLOCK', res.stderr.trim());
        }
      }
    },
    async exists(vaultId) {
      for (const s of [SERVICE, LEGACY_SERVICE]) {
        const res = await run(SECURITY, ['find-generic-password', '-s', s, '-a', account(vaultId)], {
          timeoutMs: 30_000,
        });
        if (res.code === 0) return true;
      }
      return false;
    },
  };
}
