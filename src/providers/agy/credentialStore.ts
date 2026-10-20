import path from 'node:path';
import { run } from '../../util/exec.js';
import { LockerError } from '../../util/errors.js';
import { atomicWrite, readIfExists, removeIfExists } from '../../vault/atomicWrite.js';

export interface CredentialStore {
  readonly kind: string;
  readonly location: string;
  read(): Promise<string | null>;
  write(json: string): Promise<void>;
  clear(): Promise<void>;
}

/** File-backed store, used for testing or fallback. */
export class FileStore implements CredentialStore {
  readonly kind = 'file';
  constructor(readonly location: string) {}

  async read(): Promise<string | null> {
    const text = await readIfExists(this.location);
    return text && text.trim() ? text : null;
  }

  async write(json: string): Promise<void> {
    await atomicWrite(this.location, json, 0o600);
  }

  async clear(): Promise<void> {
    await removeIfExists(this.location);
  }
}

/**
 * Windows Credential Manager store for Antigravity (`gemini:antigravity`).
 * P/Invokes Advapi32 CredRead/CredWrite/CredDelete via in-box Windows PowerShell.
 * Passwords and payloads travel through stdin as base64, never exposed in command line arguments.
 */
export class Win32CredStore implements CredentialStore {
  readonly kind = 'Windows Credential Manager';
  private readonly powershell: string;

  constructor(readonly target: string = 'gemini:antigravity', readonly userName: string = 'antigravity') {
    const root = process.env.SystemRoot || 'C:\\Windows';
    this.powershell = path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  }

  get location(): string {
    return `Credential "${this.target}" (User: ${this.userName})`;
  }

  private static readonly CSHARP_DEF = `
using System;
using System.Runtime.InteropServices;
public class AdvapiCred {
    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);
    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
    public static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);
    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
    public static extern bool CredDelete(string target, int type, int flags);
    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern void CredFree([In] IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static string Read(string target) {
        IntPtr ptr;
        if (!CredRead(target, 1, 0, out ptr)) return null;
        try {
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            byte[] bytes = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, bytes, 0, cred.CredentialBlobSize);
            return System.Text.Encoding.UTF8.GetString(bytes);
        } finally {
            CredFree(ptr);
        }
    }

    public static bool Write(string target, string userName, string secret) {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(secret);
        IntPtr blobPtr = Marshal.AllocHGlobal(bytes.Length);
        try {
            Marshal.Copy(bytes, 0, blobPtr, bytes.Length);
            CREDENTIAL cred = new CREDENTIAL {
                Type = 1,
                TargetName = target,
                UserName = userName,
                CredentialBlobSize = bytes.Length,
                CredentialBlob = blobPtr,
                Persist = 2
            };
            return CredWrite(ref cred, 0);
        } finally {
            Marshal.FreeHGlobal(blobPtr);
        }
    }

    public static bool Delete(string target) {
        return CredDelete(target, 1, 0);
    }
}
`;

  private async execPs(psScript: string, input?: string) {
    const full = `$ErrorActionPreference = 'Stop'\nAdd-Type -TypeDefinition @"\n${Win32CredStore.CSHARP_DEF}\n"@\n${psScript}`;
    const encoded = Buffer.from(full, 'utf16le').toString('base64');
    return run(this.powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
      input,
      timeoutMs: 30_000,
    });
  }

  async read(): Promise<string | null> {
    const script = `$val = [AdvapiCred]::Read('${this.target}')\nif ($val -ne $null) { [Console]::Out.Write([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($val))) }`;
    const res = await this.execPs(script);
    if (res.code !== 0) {
      throw new LockerError('Failed to query Windows Credential Manager.', 'E_STORE', res.stderr.trim());
    }
    const stdout = res.stdout.trim();
    if (!stdout) return null;
    return Buffer.from(stdout, 'base64').toString('utf8');
  }

  async write(json: string): Promise<void> {
    const script = `$in = [Console]::In.ReadToEnd().Trim()\n$secret = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($in))\n$ok = [AdvapiCred]::Write('${this.target}', '${this.userName}', $secret)\nif (-not $ok) { throw 'CredWrite failed' }`;
    const res = await this.execPs(script, Buffer.from(json, 'utf8').toString('base64'));
    if (res.code !== 0) {
      throw new LockerError('Failed to write to Windows Credential Manager.', 'E_STORE', res.stderr.trim());
    }
  }

  async clear(): Promise<void> {
    const script = `[AdvapiCred]::Delete('${this.target}') | Out-Null`;
    const res = await this.execPs(script);
    if (res.code !== 0) {
      throw new LockerError('Failed to clear credentials from Windows Credential Manager.', 'E_STORE', res.stderr.trim());
    }
  }
}

const SECURITY = '/usr/bin/security';
const ITEM_NOT_FOUND = 44;
const MAX_INTERACTIVE_LINE = 3800;

/** macOS Keychain store for Antigravity (service `gemini`, account `antigravity`). */
export class KeychainStore implements CredentialStore {
  readonly kind = 'macOS Keychain';
  constructor(
    readonly service: string = 'gemini',
    readonly account: string = 'antigravity',
    readonly fallback?: FileStore,
  ) {}

  get location(): string {
    return `Keychain item "${this.service}" (account "${this.account}")`;
  }

  async read(): Promise<string | null> {
    const res = await run(SECURITY, ['find-generic-password', '-s', this.service, '-a', this.account, '-w'], { timeoutMs: 60_000 });
    if (res.code === 0 && res.stdout.trim()) return res.stdout.replace(/\n$/, '');
    if (res.code !== 0 && res.code !== ITEM_NOT_FOUND) {
      throw new LockerError('Could not read credentials from Keychain.', 'E_STORE', res.stderr.trim());
    }
    return this.fallback ? this.fallback.read() : null;
  }

  async write(json: string): Promise<void> {
    const oneLine = JSON.stringify(JSON.parse(json));
    const hex = Buffer.from(oneLine, 'utf8').toString('hex');
    await this.clear();
    const line = `add-generic-password -U -s "${this.service}" -a "${this.account}" -X ${hex}\n`;
    const res =
      line.length <= MAX_INTERACTIVE_LINE
        ? await run(SECURITY, ['-i'], { input: line, timeoutMs: 60_000 })
        : await run(SECURITY, ['add-generic-password', '-U', '-s', this.service, '-a', this.account, '-X', hex], { timeoutMs: 60_000 });
    if (res.code !== 0 || /error/i.test(res.stderr)) {
      throw new LockerError('Could not write credentials to Keychain.', 'E_STORE', res.stderr.trim());
    }
    if (this.fallback) await this.fallback.clear();
  }

  async clear(): Promise<void> {
    for (let i = 0; i < 10; i++) {
      const res = await run(SECURITY, ['delete-generic-password', '-s', this.service, '-a', this.account], { timeoutMs: 30_000 });
      if (res.code === ITEM_NOT_FOUND) break;
      if (res.code !== 0) {
        throw new LockerError('Could not remove credentials from Keychain.', 'E_STORE', res.stderr.trim());
      }
    }
    if (this.fallback) await this.fallback.clear();
  }
}

/** Linux Secret Service store (via `secret-tool`), with fallback to file. */
export class LinuxSecretStore implements CredentialStore {
  readonly kind = 'Secret Service';
  constructor(
    readonly service: string = 'gemini',
    readonly account: string = 'antigravity',
    readonly fallback: FileStore,
  ) {}

  get location(): string {
    return `Secret Service "${this.service}" (account "${this.account}")`;
  }

  async read(): Promise<string | null> {
    const res = await run('secret-tool', ['lookup', 'service', this.service, 'account', this.account], { timeoutMs: 15_000 });
    if (res.code === 0 && res.stdout.trim()) return res.stdout.trim();
    return this.fallback.read();
  }

  async write(json: string): Promise<void> {
    const res = await run(
      'secret-tool',
      ['store', '--label=Gemini Antigravity', 'service', this.service, 'account', this.account],
      { input: json, timeoutMs: 15_000 },
    );
    if (res.code !== 0) {
      // If secret-tool fails (e.g. headless or missing dbus), use fallback file
      await this.fallback.write(json);
      return;
    }
    await this.fallback.clear();
  }

  async clear(): Promise<void> {
    await run('secret-tool', ['clear', 'service', this.service, 'account', this.account], { timeoutMs: 15_000 });
    await this.fallback.clear();
  }
}
