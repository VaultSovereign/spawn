import { isNumber, isString, toRecord } from "./type-guards";

export type ArtifactCategory = "receipt" | "log" | "output";
export type ArtifactType =
  | "declaration-receipt"
  | "environment-receipt"
  | "manifest-lock"
  | "step-ledger"
  | "artifact-manifest"
  | "termination-receipt"
  | "integrity-manifest"
  | "execution-envelope"
  | "stdout-transcript"
  | "stderr-transcript"
  | "interactive-transcript"
  | "pty-timing-log"
  | "session-summary"
  | "terminal-capture-meta"
  | "output";

export interface ArtifactRecord {
  artifact_id: string;
  logical_name: string;
  path: string;
  media_type: string;
  byte_size: number;
  sha256: string;
  provenance_step?: string;
  category: ArtifactCategory;
  artifact_type: ArtifactType;
}

function isArtifactType(value: unknown): value is ArtifactType {
  return (
    value === "declaration-receipt" ||
    value === "environment-receipt" ||
    value === "manifest-lock" ||
    value === "step-ledger" ||
    value === "artifact-manifest" ||
    value === "termination-receipt" ||
    value === "integrity-manifest" ||
    value === "execution-envelope" ||
    value === "stdout-transcript" ||
    value === "stderr-transcript" ||
    value === "interactive-transcript" ||
    value === "pty-timing-log" ||
    value === "session-summary" ||
    value === "terminal-capture-meta" ||
    value === "output"
  );
}

export function isArtifactRecord(value: unknown): value is ArtifactRecord {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return (
    isString(record.artifact_id) &&
    isString(record.logical_name) &&
    isString(record.path) &&
    isString(record.media_type) &&
    isNumber(record.byte_size) &&
    isString(record.sha256) &&
    (record.provenance_step === undefined || isString(record.provenance_step)) &&
    (record.category === "receipt" || record.category === "log" || record.category === "output") &&
    isArtifactType(record.artifact_type)
  );
}
