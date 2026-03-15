import { isString, toRecord } from "./type-guards";

export type AttestationState = "none" | "present-unverified" | "verified";

export interface WitnessReceipt {
  schema_version: string;
  canonicalization_version: string;
  subject: "record_digest";
  witness_type: "spawn-ed25519";
  run_id: string;
  record_digest: string;
  bundle_digest?: string;
  signer: {
    key_id: string;
    identity_hint?: string;
    verifier: string;
  };
  signed_at: string;
}

export interface SignatureReceipt {
  schema_version: string;
  algorithm: "ed25519";
  key_id: string;
  verifier: string;
  payload_type: "spawn-attestation-statement";
  payload_digest: string;
  signature: string;
}

export function isWitnessReceipt(value: unknown): value is WitnessReceipt {
  const record = toRecord(value);
  const signer = record ? toRecord(record.signer) : null;
  if (!record || !signer) {
    return false;
  }
  return (
    isString(record.schema_version) &&
    isString(record.canonicalization_version) &&
    record.subject === "record_digest" &&
    record.witness_type === "spawn-ed25519" &&
    isString(record.run_id) &&
    isString(record.record_digest) &&
    (record.bundle_digest === undefined || isString(record.bundle_digest)) &&
    isString(signer.key_id) &&
    (signer.identity_hint === undefined || isString(signer.identity_hint)) &&
    isString(signer.verifier) &&
    isString(record.signed_at)
  );
}

export function isSignatureReceipt(value: unknown): value is SignatureReceipt {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return (
    isString(record.schema_version) &&
    record.algorithm === "ed25519" &&
    isString(record.key_id) &&
    isString(record.verifier) &&
    record.payload_type === "spawn-attestation-statement" &&
    isString(record.payload_digest) &&
    isString(record.signature)
  );
}
