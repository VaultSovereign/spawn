import type { StoredTrustState, TrustStore, TrustStoreEntry } from "@openrouter/spawn-shared";
import type { VerifyResult } from "./execution-witness.js";

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { getErrorMessage, isExecutionRecord, isTrustStore, tryCatch } from "@openrouter/spawn-shared";
import { getAttestationVerifierKeyPath, getTrustStorePath } from "./paths.js";

const TRUST_STORE_SCHEMA_VERSION = "spawn-trust-store/v1";

interface AddTrustEntryOptions {
  keyId: string;
  label?: string;
  scope?: string;
  metadata?: Record<string, string>;
  identityHint?: string;
  verifier?: string;
  state?: StoredTrustState;
  expiresAt?: string;
}

function writeJson(filePath: string, data: unknown): void {
  mkdirSync(dirname(filePath), {
    recursive: true,
  });
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", {
    mode: 0o600,
  });
}

function createEmptyTrustStore(): TrustStore {
  return {
    schema_version: TRUST_STORE_SCHEMA_VERSION,
    entries: [],
  };
}

export function loadTrustStore(): TrustStore {
  const trustStorePath = getTrustStorePath();
  if (!existsSync(trustStorePath)) {
    return createEmptyTrustStore();
  }
  const parsed = tryCatch(() => JSON.parse(readFileSync(trustStorePath, "utf-8")));
  if (!parsed.ok || !isTrustStore(parsed.data)) {
    throw new Error(`Invalid trust store at ${trustStorePath}`);
  }
  return parsed.data;
}

function saveTrustStore(store: TrustStore): void {
  writeJson(getTrustStorePath(), store);
}

export function listTrustEntries(): TrustStoreEntry[] {
  return loadTrustStore()
    .entries.slice()
    .sort((a, b) => a.label.localeCompare(b.label));
}

export function addTrustEntry(options: AddTrustEntryOptions): TrustStoreEntry {
  const verifierKeyPath = getAttestationVerifierKeyPath(options.keyId);
  if (!existsSync(verifierKeyPath)) {
    throw new Error(`Verifier key not found for ${options.keyId}`);
  }

  const store = loadTrustStore();
  const now = new Date().toISOString();
  const nextEntry: TrustStoreEntry = {
    key_id: options.keyId,
    label: options.label ?? options.keyId,
    algorithm: "ed25519",
    state: options.state ?? "trusted",
    scope: options.scope ?? "global",
    created_at: now,
    ...(options.state === "revoked"
      ? {
          revoked_at: now,
        }
      : {}),
    ...(options.expiresAt
      ? {
          expires_at: options.expiresAt,
        }
      : {}),
    ...(options.metadata
      ? {
          metadata: options.metadata,
        }
      : {}),
    ...(options.identityHint
      ? {
          identity_hint: options.identityHint,
        }
      : {}),
    ...(options.verifier
      ? {
          verifier: options.verifier,
        }
      : {}),
  };

  const existingIndex = store.entries.findIndex((entry) => entry.key_id === options.keyId);
  if (existingIndex >= 0) {
    store.entries[existingIndex] = {
      ...store.entries[existingIndex],
      ...nextEntry,
      created_at: store.entries[existingIndex].created_at,
      revoked_at: nextEntry.state === "revoked" ? now : undefined,
    };
  } else {
    store.entries.push(nextEntry);
  }

  saveTrustStore(store);
  return store.entries.find((entry) => entry.key_id === options.keyId)!;
}

export function removeTrustEntry(keyId: string): boolean {
  const store = loadTrustStore();
  const nextEntries = store.entries.filter((entry) => entry.key_id !== keyId);
  if (nextEntries.length === store.entries.length) {
    return false;
  }
  saveTrustStore({
    ...store,
    entries: nextEntries,
  });
  return true;
}

function loadExecutionEnvelope(rootDir: string) {
  const parsed = tryCatch(() => JSON.parse(readFileSync(join(rootDir, "envelope.json"), "utf-8")));
  if (!parsed.ok || !isExecutionRecord(parsed.data)) {
    return null;
  }
  return parsed.data;
}

function scopeAllowsEntry(scope: string, runbook: string, target: string): boolean {
  if (scope === "global") {
    return true;
  }
  if (scope === `runbook:${runbook}`) {
    return true;
  }
  if (scope === `target:${target}`) {
    return true;
  }
  return scope === `runbook-target:${runbook}@${target}`;
}

function evaluateTrustState(rootDir: string, result: VerifyResult): VerifyResult["trust"] {
  if (result.attestation.state === "none") {
    return {
      ok: true,
      state: "none",
    };
  }

  if (result.attestation.state !== "verified" || !result.attestation.key_id) {
    return {
      ok: false,
      state: "unknown",
      key_id: result.attestation.key_id,
      reason: "attestation-not-verified",
    };
  }

  const envelope = loadExecutionEnvelope(rootDir);
  if (!envelope) {
    return {
      ok: false,
      state: "unknown",
      key_id: result.attestation.key_id,
      reason: "execution-record-unavailable",
    };
  }

  const trustEntry = loadTrustStore().entries.find((entry) => entry.key_id === result.attestation.key_id);
  if (!trustEntry) {
    return {
      ok: false,
      state: "unknown",
      key_id: result.attestation.key_id,
      reason: "signer-not-in-trust-store",
    };
  }

  if (!scopeAllowsEntry(trustEntry.scope, envelope.runbook, envelope.target)) {
    return {
      ok: false,
      state: "disallowed",
      key_id: trustEntry.key_id,
      label: trustEntry.label,
      scope: trustEntry.scope,
      reason: "scope-mismatch",
    };
  }

  if (trustEntry.expires_at && Date.parse(trustEntry.expires_at) <= Date.now()) {
    return {
      ok: false,
      state: "expired",
      key_id: trustEntry.key_id,
      label: trustEntry.label,
      scope: trustEntry.scope,
      reason: "trust-entry-expired",
    };
  }

  if (trustEntry.state === "revoked") {
    return {
      ok: false,
      state: "revoked",
      key_id: trustEntry.key_id,
      label: trustEntry.label,
      scope: trustEntry.scope,
      reason: "trust-entry-revoked",
    };
  }

  if (trustEntry.state === "disallowed") {
    return {
      ok: false,
      state: "disallowed",
      key_id: trustEntry.key_id,
      label: trustEntry.label,
      scope: trustEntry.scope,
      reason: "trust-entry-disallowed",
    };
  }

  return {
    ok: true,
    state: "trusted",
    key_id: trustEntry.key_id,
    label: trustEntry.label,
    scope: trustEntry.scope,
  };
}

function recomputePolicy(rootDir: string, result: VerifyResult): VerifyResult {
  const envelope = loadExecutionEnvelope(rootDir);
  if (!envelope) {
    return result;
  }

  const nextErrors = result.errors.filter(
    (entry) =>
      !entry.startsWith("Attestation required by policy") &&
      !entry.startsWith("Trusted signer required by policy") &&
      !entry.startsWith("Signer not allowed by policy"),
  );

  const attestationRequired = envelope.policy.attestation_policy === "required";
  const attestationOk = !attestationRequired || result.attestation.state === "verified";
  if (!attestationOk) {
    nextErrors.push("Attestation required by policy but not verified");
  }

  const trustRequired =
    envelope.policy.trust_policy === "trusted-required" || envelope.policy.trust_policy === "allowed-set-required";
  const trustOk = !trustRequired || result.trust.state === "trusted";
  if (!trustOk) {
    nextErrors.push("Trusted signer required by policy but not accepted");
  }

  const signerAllowed =
    envelope.policy.trust_policy !== "allowed-set-required" ||
    (result.attestation.key_id !== undefined && envelope.policy.trusted_signers.includes(result.attestation.key_id));
  if (!signerAllowed) {
    nextErrors.push(`Signer not allowed by policy: ${result.attestation.key_id ?? "unknown"}`);
  }

  const policyOk =
    result.capture.ok && result.policy.missing_artifacts.length === 0 && attestationOk && trustOk && signerAllowed;

  return {
    ...result,
    ok: result.integrity.ok && policyOk && result.transport.ok,
    verified: result.integrity.ok && policyOk && result.transport.ok,
    errors: nextErrors,
    policy: {
      ...result.policy,
      ok: policyOk,
    },
  };
}

export function applyTrustVerification(rootDir: string, result: VerifyResult): VerifyResult {
  const nextResult = {
    ...result,
    trust: evaluateTrustState(rootDir, result),
  };
  return recomputePolicy(rootDir, nextResult);
}

export function formatTrustList(entries: TrustStoreEntry[]): string[] {
  if (entries.length === 0) {
    return [
      "No trusted signers configured.",
    ];
  }
  return entries.map((entry) => {
    const suffix = entry.state === "trusted" ? "" : ` (${entry.state})`;
    return `${entry.key_id}  ${entry.label}  scope=${entry.scope}${suffix}`;
  });
}

export function describeTrustStoreError(error: unknown): string {
  return getErrorMessage(error);
}
