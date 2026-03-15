import { isString, toRecord } from "./type-guards";

export interface ProofBundleReceipt {
  schema_version: string;
  bundle_format_version: string;
  canonicalization_version: string;
  root_directory: string;
  run_id: string;
  record_digest: string;
  record_digest_algorithm: string;
  bundle_digest_algorithm: string;
  built_at: string;
}

export function isProofBundleReceipt(value: unknown): value is ProofBundleReceipt {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return (
    isString(record.schema_version) &&
    isString(record.bundle_format_version) &&
    isString(record.canonicalization_version) &&
    isString(record.root_directory) &&
    isString(record.run_id) &&
    isString(record.record_digest) &&
    isString(record.record_digest_algorithm) &&
    isString(record.bundle_digest_algorithm) &&
    isString(record.built_at)
  );
}
