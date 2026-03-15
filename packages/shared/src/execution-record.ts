import type { ArtifactRecord } from "./artifact-schema";
import type {
  AttestationPolicy,
  CaptureModeReceipt,
  DeclarationReceipt,
  EnvironmentReceipt,
  ExecutionStep,
  TerminationReceipt,
  TranscriptPolicy,
  TrustPolicy,
  WitnessCompleteness,
} from "./receipt-schema";
import type { TrustState } from "./trust-schema";

import { isArtifactRecord } from "./artifact-schema";
import {
  isCaptureModeReceipt,
  isDeclarationReceipt,
  isEnvironmentReceipt,
  isExecutionStep,
  isTerminationReceipt,
  isWitnessCompleteness,
} from "./receipt-schema";
import { isString, toRecord } from "./type-guards";

export interface ExecutionRecord {
  run_id: string;
  runbook: string;
  target: string;
  version: string;
  inputs: {
    cli_args: string[];
    config_path?: string;
    config_sha256?: string;
    env_var_names: string[];
  };
  environment: EnvironmentReceipt;
  steps: ExecutionStep[];
  artifacts: ArtifactRecord[];
  result: TerminationReceipt | null;
  witness_completeness: WitnessCompleteness;
  capture_mode: CaptureModeReceipt;
  policy: {
    transcript_policy: TranscriptPolicy;
    attestation_policy: AttestationPolicy;
    trust_policy: TrustPolicy;
    required_artifacts: string[];
    expected_artifacts: string[];
    trusted_signers: string[];
  };
  timestamps: {
    declared_at: string;
    started_at: string;
    ended_at?: string;
  };
  hashes: Record<string, string>;
  witness: {
    witness_level: string;
    tool: string;
    declaration: DeclarationReceipt;
    trust_capability?: {
      verifier: string;
      trust_store: TrustState;
    };
  };
}

export function isExecutionRecord(value: unknown): value is ExecutionRecord {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  if (
    !isString(record.run_id) ||
    !isString(record.runbook) ||
    !isString(record.target) ||
    !isString(record.version) ||
    typeof record.inputs !== "object" ||
    record.inputs === null ||
    !isEnvironmentReceipt(record.environment) ||
    !Array.isArray(record.steps) ||
    !record.steps.every(isExecutionStep) ||
    !Array.isArray(record.artifacts) ||
    !record.artifacts.every(isArtifactRecord) ||
    (record.result !== null && !isTerminationReceipt(record.result)) ||
    !isWitnessCompleteness(record.witness_completeness) ||
    !isCaptureModeReceipt(record.capture_mode) ||
    typeof record.policy !== "object" ||
    record.policy === null ||
    typeof record.timestamps !== "object" ||
    record.timestamps === null ||
    typeof record.hashes !== "object" ||
    record.hashes === null ||
    typeof record.witness !== "object" ||
    record.witness === null
  ) {
    return false;
  }

  const witness = toRecord(record.witness);
  const policy = toRecord(record.policy);
  return (
    !!witness &&
    !!policy &&
    isString(witness.witness_level) &&
    isString(witness.tool) &&
    isDeclarationReceipt(witness.declaration) &&
    (policy.transcript_policy === "none" ||
      policy.transcript_policy === "optional" ||
      policy.transcript_policy === "required") &&
    (policy.attestation_policy === "none" ||
      policy.attestation_policy === "optional" ||
      policy.attestation_policy === "required") &&
    (policy.trust_policy === "any-valid" ||
      policy.trust_policy === "trusted-required" ||
      policy.trust_policy === "allowed-set-required") &&
    Array.isArray(policy.required_artifacts) &&
    policy.required_artifacts.every(isString) &&
    Array.isArray(policy.expected_artifacts) &&
    policy.expected_artifacts.every(isString) &&
    Array.isArray(policy.trusted_signers) &&
    policy.trusted_signers.every(isString)
  );
}
