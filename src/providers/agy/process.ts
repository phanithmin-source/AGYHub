import path from 'node:path';
import { run } from '../../util/exec.js';
import type { RunningProcess } from '../Provider.js';

interface RawProcess {
  pid: number;
  name: string;
  commandLine: string;
}

export function isAgyProcess(p: RawProcess): boolean {
  const base = path.win32.basename(path.posix.basename(p.name)).toLowerCase();
  return (
    base === 'agy' ||
    base === 'agy.exe' ||
    base === 'antigravity' ||
    base === 'antigravity.exe'
  );
}

/** Processes that may hold Antigravity credentials in memory and write them back later. */
export async function findAgyProcesses(platform = process.platform): Promise<RunningProcess[]> {
  const all = platform === 'win32' ? await listWindows() : await listPosix();
  return all.filter((p) => p.pid !== process.pid && isAgyProcess(p)).map(({ pid, name }) => ({ pid, name }));
}

async function listWindows(): Promise<RawProcess[]> {
  const ps = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const script =
    "Get-CimInstance Win32_Process -Filter \"Name='agy.exe' OR Name='antigravity.exe'\" | " +
    'ForEach-Object { "$($_.ProcessId)`t$($_.Name)`t$($_.CommandLine)" }';
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const res = await run(ps, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
    timeoutMs: 30_000,
  });
  return res.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const [pid = '', name = '', ...rest] = line.split('\t');
      return { pid: Number(pid), name, commandLine: rest.join('\t') };
    })
    .filter((p) => Number.isFinite(p.pid));
}

async function listPosix(): Promise<RawProcess[]> {
  const res = await run('ps', ['-axo', 'pid=,comm=,args='], { timeoutMs: 30_000 });
  return res.stdout
    .split('\n')
    .map((line) => line.trim().match(/^(\d+)\s+(\S+)\s*(.*)$/))
    .filter((m): m is RegExpMatchArray => m !== null)
    .map((m) => ({ pid: Number(m[1]), name: m[2] ?? '', commandLine: m[3] ?? '' }));
}
