import fs from 'node:fs';
import path from 'node:path';
import { run } from '../../util/exec.js';
import { atomicWrite, readIfExists, removeIfExists } from '../atomicWrite.js';
import { LockerError } from '../../util/errors.js';
import type { OsKeyCache } from './index.js';

/**
 * Windows DPAPI (CurrentUser scope) via the in-box Windows PowerShell 5.1, so no native
 * Node module is needed. The key travels over stdin as base64, never on the command line.
 * The protected blob only decrypts for this Windows user on this machine.
 */
function powershellPath(): string {
  const root = process.env.SystemRoot || 'C:\\Windows';
  return path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

function script(op: 'Protect' | 'Unprotect', vaultId: string): string {
  if (!/^[0-9a-f]+$/i.test(vaultId)) throw new Error('invalid vault id');
  if (op === 'Protect') {
    return [
      "$ErrorActionPreference = 'Stop'",
      'Add-Type -AssemblyName System.Security',
      '$in = [Console]::In.ReadToEnd().Trim()',
      '$bytes = [Convert]::FromBase64String($in)',
      `$entropy = [Text.Encoding]::UTF8.GetBytes('agyhub:${vaultId}')`,
      `$out = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)`,
      '[Console]::Out.Write([Convert]::ToBase64String($out))',
    ].join('; ');
  }
  // Unprotect: try agyhub prefix, fallback to legacy ai-locker prefix
  return [
    "$ErrorActionPreference = 'Stop'",
    'Add-Type -AssemblyName System.Security',
    '$in = [Console]::In.ReadToEnd().Trim()',
    '$bytes = [Convert]::FromBase64String($in)',
    'try {',
    `  $entropy = [Text.Encoding]::UTF8.GetBytes('agyhub:${vaultId}')`,
    `  $out = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)`,
    '} catch {',
    `  $entropy = [Text.Encoding]::UTF8.GetBytes('ai-locker:${vaultId}')`,
    `  $out = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)`,
    '}',
    '[Console]::Out.Write([Convert]::ToBase64String($out))',
  ].join('; ');
}

async function dpapi(op: 'Protect' | 'Unprotect', data: Buffer, vaultId: string): Promise<Buffer> {
  const ps = powershellPath();
  if (!fs.existsSync(ps)) {
    throw new LockerError('Windows PowerShell was not found, so DPAPI is unavailable.', 'E_OS_UNLOCK');
  }
  const encoded = Buffer.from(script(op, vaultId), 'utf16le').toString('base64');
  const res = await run(
    ps,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
    { input: data.toString('base64'), timeoutMs: 30_000 },
  );
  if (res.code !== 0 || !res.stdout.trim()) {
    throw new LockerError(`Windows DPAPI ${op} failed.`, 'E_OS_UNLOCK', res.stderr.trim().split('\n')[0]);
  }
  return Buffer.from(res.stdout.trim(), 'base64');
}

export function win32Cache(blobPath: string): OsKeyCache {
  return {
    name: 'Windows DPAPI (CurrentUser)',
    async store(vaultId, vdk) {
      const blob = await dpapi('Protect', vdk, vaultId);
      await atomicWrite(blobPath, blob.toString('base64'));
    },
    async load(vaultId) {
      const b64 = await readIfExists(blobPath);
      if (!b64) return null;
      return dpapi('Unprotect', Buffer.from(b64.trim(), 'base64'), vaultId);
    },
    async clear() {
      await removeIfExists(blobPath);
    },
    async exists() {
      return (await readIfExists(blobPath)) !== null;
    },
  };
}
