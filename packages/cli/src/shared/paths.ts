// shared/paths.ts — Centralized filesystem path resolution
//
// All path helpers live here. Production code imports from this module;
// no other module should call homedir() or construct spawn-specific paths directly.

import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

/** Return the user's home directory, preferring $HOME over os.homedir(). */
export function getUserHome(): string {
  return process.env.HOME || homedir();
}

/** Returns the directory for spawn data, respecting SPAWN_HOME env var.
 *  SPAWN_HOME must be an absolute path if set; relative paths are rejected
 *  to prevent unintended file writes. */
export function getSpawnDir(): string {
  const spawnHome = process.env.SPAWN_HOME;
  if (!spawnHome) {
    return join(getUserHome(), ".spawn");
  }
  // Require absolute path to prevent path traversal via relative paths
  if (!isAbsolute(spawnHome)) {
    throw new Error(
      `SPAWN_HOME must be an absolute path (got "${spawnHome}").\n` + "Example: export SPAWN_HOME=/home/user/.spawn",
    );
  }
  // Resolve to canonical form (collapses .. segments)
  const resolved = resolve(spawnHome);

  // SECURITY: Prevent path traversal to system directories
  // Even though the path is absolute, resolve() can normalize paths like
  // /tmp/../../root/.spawn to /root/.spawn, potentially allowing unauthorized
  // file writes to sensitive directories.
  const userHome = getUserHome();
  const normalizedResolved = resolved.replaceAll("\\", "/");
  const normalizedHome = userHome.replaceAll("\\", "/");
  if (!normalizedResolved.startsWith(normalizedHome + "/") && normalizedResolved !== normalizedHome) {
    throw new Error("SPAWN_HOME must be within your home directory.\n" + `Got: ${resolved}\n` + `Home: ${userHome}`);
  }

  return resolved;
}

/** Path to the spawn history file. */
export function getHistoryPath(): string {
  return join(getSpawnDir(), "history.json");
}

/** Path to the directory containing witnessed execution records. */
export function getRunsDir(): string {
  return join(getSpawnDir(), "runs");
}

/** Path to a specific witnessed execution directory. */
export function getRunDir(runId: string): string {
  return join(getRunsDir(), runId);
}

/** Path to the attestation metadata directory. */
export function getAttestationDir(): string {
  return join(getSpawnDir(), "attestation");
}

/** Path to the local signing key directory. */
export function getAttestationKeysDir(): string {
  return join(getAttestationDir(), "keys");
}

/** Path to the verifier public key directory used for cryptographic checks. */
export function getAttestationVerifiersDir(): string {
  return join(getAttestationDir(), "verifiers");
}

/** Path to the default signing private key. */
export function getDefaultAttestationPrivateKeyPath(): string {
  return join(getAttestationKeysDir(), "default-private.pem");
}

/** Path to the default signing public key. */
export function getDefaultAttestationPublicKeyPath(): string {
  return join(getAttestationKeysDir(), "default-public.pem");
}

/** Path to a verifier public key for the given key ID. */
export function getAttestationVerifierKeyPath(keyId: string): string {
  return join(getAttestationVerifiersDir(), `${keyId}.pem`);
}

/** Backward-compatible alias for verifier key lookup. */
export function getTrustedAttestationKeyPath(keyId: string): string {
  return getAttestationVerifierKeyPath(keyId);
}

/** Path to the trust policy directory. */
export function getTrustDir(): string {
  return join(getSpawnDir(), "trust");
}

/** Path to the local trust store file. */
export function getTrustStorePath(): string {
  return join(getTrustDir(), "trust-store.json");
}

/**
 * Return the path to the per-cloud config file: ~/.config/spawn/{cloud}.json
 * Shared by all cloud modules to avoid repeating the same path construction.
 */
export function getSpawnCloudConfigPath(cloud: string): string {
  return join(getUserHome(), ".config", "spawn", `${cloud}.json`);
}

/** Return the path to the spawn preferences file: ~/.config/spawn/preferences.json */
export function getSpawnPreferencesPath(): string {
  return join(getUserHome(), ".config", "spawn", "preferences.json");
}

/** Return the cache directory for spawn, respecting XDG_CACHE_HOME. */
export function getCacheDir(): string {
  return join(process.env.XDG_CACHE_HOME || join(getUserHome(), ".cache"), "spawn");
}

/** Return the path to the cached manifest file. */
export function getCacheFile(): string {
  return join(getCacheDir(), "manifest.json");
}

/** Return the path to the update-failed sentinel file. */
export function getUpdateFailedPath(): string {
  return join(getUserHome(), ".config", "spawn", ".update-failed");
}

/** Return the path to the user's ~/.ssh directory. */
export function getSshDir(): string {
  return join(getUserHome(), ".ssh");
}

/** Return the system temp directory (wraps os.tmpdir()). */
export function getTmpDir(): string {
  return tmpdir();
}
