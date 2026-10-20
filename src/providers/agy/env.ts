import os from 'node:os';
import path from 'node:path';

export interface AgyEnv {
  platform: NodeJS.Platform;
  /** Directory holding config, logs, settings (~/.gemini/antigravity-cli by default). */
  configDir: string;
  keychainService: string;
  keychainAccount: string;
  winTarget: string;
}

export function resolveAgyEnv(env: NodeJS.ProcessEnv = process.env, platform = process.platform): AgyEnv {
  const custom = env.AGY_CONFIG_DIR || env.GEMINI_CLI_HOME;
  const configDir = custom || path.join(os.homedir(), '.gemini', 'antigravity-cli');
  return {
    platform,
    configDir,
    keychainService: 'gemini',
    keychainAccount: 'antigravity',
    winTarget: 'gemini:antigravity',
  };
}

/** Environment variables that make Antigravity ignore the stored OS login. */
export const OVERRIDING_ENV_VARS = [
  'GEMINI_API_KEY',
  'AGY_ADC_AUTH',
  'GOOGLE_APPLICATION_CREDENTIALS',
] as const;

/** A copy of the environment without credential overrides, for spawning `agy`. */
export function cleanAgyEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const copy = { ...env };
  for (const k of OVERRIDING_ENV_VARS) delete copy[k];
  return copy;
}
