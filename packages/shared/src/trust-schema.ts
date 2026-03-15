import { isString, toRecord } from "./type-guards";

export type TrustState = "none" | "unknown" | "trusted" | "revoked" | "expired" | "disallowed";
export type StoredTrustState = "trusted" | "revoked" | "disallowed";
export type AttestationPolicy = "none" | "optional" | "required";
export type TrustPolicy = "any-valid" | "trusted-required" | "allowed-set-required";

export interface TrustStoreEntry {
  key_id: string;
  label: string;
  algorithm: "ed25519";
  state: StoredTrustState;
  scope: string;
  created_at: string;
  revoked_at?: string;
  expires_at?: string;
  metadata?: Record<string, string>;
  identity_hint?: string;
  verifier?: string;
}

export interface TrustStore {
  schema_version: string;
  entries: TrustStoreEntry[];
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return Object.values(value).every((entry) => isString(entry));
}

export function isTrustStoreEntry(value: unknown): value is TrustStoreEntry {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return (
    isString(record.key_id) &&
    isString(record.label) &&
    record.algorithm === "ed25519" &&
    (record.state === "trusted" || record.state === "revoked" || record.state === "disallowed") &&
    isString(record.scope) &&
    isString(record.created_at) &&
    (record.revoked_at === undefined || isString(record.revoked_at)) &&
    (record.expires_at === undefined || isString(record.expires_at)) &&
    (record.metadata === undefined || isStringRecord(record.metadata)) &&
    (record.identity_hint === undefined || isString(record.identity_hint)) &&
    (record.verifier === undefined || isString(record.verifier))
  );
}

export function isTrustStore(value: unknown): value is TrustStore {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return isString(record.schema_version) && Array.isArray(record.entries) && record.entries.every(isTrustStoreEntry);
}
