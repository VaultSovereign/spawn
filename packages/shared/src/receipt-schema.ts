import { isNumber, isString, toRecord } from "./type-guards";

export type StepStatus = "running" | "success" | "failed" | "warning" | "skipped";
export type RunStatus = "success" | "failed" | "aborted" | "timeout";
export type WitnessCompletenessStatus = "complete" | "partial" | "absent";
export type TranscriptPolicy = "none" | "optional" | "required";
export type TranscriptCaptureMode = "none" | "best-effort" | "pty-recorded" | "fully-structured";
export type StreamCaptureMode = "none" | "streamed";
export type PtyCaptureMode = "none" | "best-effort" | "pty-recorded";
export type AttestationPolicy = "none" | "optional" | "required";
export type TrustPolicy = "any-valid" | "trusted-required" | "allowed-set-required";

export interface EnvVarReceipt {
  name: string;
  present: boolean;
}

export interface DeclarationReceipt {
  run_id: string;
  runbook: string;
  target: string;
  version: string;
  entrypoint: string;
  resolved_entrypoint?: string;
  spawn_commit?: string;
  manifest_sha256?: string;
  config_path?: string;
  config_sha256?: string;
  cli_args: string[];
  env_vars: EnvVarReceipt[];
  operator?: {
    username?: string;
    hostname?: string;
    git_name?: string;
    git_email?: string;
  };
  declared_at: string;
}

export interface EnvironmentReceipt {
  cloud_provider: string;
  region?: string;
  instance_type?: string;
  os?: string;
  image_id?: string;
  public_ip?: string;
  private_ip?: string;
  connection_user?: string;
  server_id?: string;
  server_name?: string;
  runtimes: Record<string, string>;
  installed_binaries: string[];
  captured_at: string;
}

export interface WitnessCompleteness {
  declare: WitnessCompletenessStatus;
  environment: WitnessCompletenessStatus;
  step_ledger: WitnessCompletenessStatus;
  artifact_manifest: WitnessCompletenessStatus;
  integrity_manifest: WitnessCompletenessStatus;
  interactive_transcript: WitnessCompletenessStatus;
}

export interface CaptureModeReceipt {
  interactive_transcript: TranscriptCaptureMode;
  stdout: StreamCaptureMode;
  stderr: StreamCaptureMode;
  pty: PtyCaptureMode;
}

export interface StepCaptureStatus {
  interactive_transcript?: WitnessCompletenessStatus;
  stdout?: WitnessCompletenessStatus;
  stderr?: WitnessCompletenessStatus;
  pty?: WitnessCompletenessStatus;
}

export interface ExecutionStep {
  step_id: string;
  name: string;
  started_at: string;
  ended_at?: string;
  exit_code?: number;
  stdout_hash?: string;
  stderr_hash?: string;
  artifact_ids: string[];
  retry_count: number;
  status: StepStatus;
  capture_status?: StepCaptureStatus;
  error?: string;
}

export interface TerminationReceipt {
  status: RunStatus;
  cleanup_attempted: boolean;
  cleanup_succeeded: boolean | null;
  surviving_resources: Array<Record<string, string>>;
  final_exit_code: number;
  final_digest: string;
  finished_at: string;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => isString(item));
}

function isWitnessCompletenessStatus(value: unknown): value is WitnessCompletenessStatus {
  return value === "complete" || value === "partial" || value === "absent";
}

function isStepStatus(value: unknown): value is StepStatus {
  return value === "running" || value === "success" || value === "failed" || value === "warning" || value === "skipped";
}

function isRunStatus(value: unknown): value is RunStatus {
  return value === "success" || value === "failed" || value === "aborted" || value === "timeout";
}

export function isWitnessCompleteness(value: unknown): value is WitnessCompleteness {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return (
    isWitnessCompletenessStatus(record.declare) &&
    isWitnessCompletenessStatus(record.environment) &&
    isWitnessCompletenessStatus(record.step_ledger) &&
    isWitnessCompletenessStatus(record.artifact_manifest) &&
    isWitnessCompletenessStatus(record.integrity_manifest) &&
    isWitnessCompletenessStatus(record.interactive_transcript)
  );
}

export function isCaptureModeReceipt(value: unknown): value is CaptureModeReceipt {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return (
    (record.interactive_transcript === "none" ||
      record.interactive_transcript === "best-effort" ||
      record.interactive_transcript === "pty-recorded" ||
      record.interactive_transcript === "fully-structured") &&
    (record.stdout === "none" || record.stdout === "streamed") &&
    (record.stderr === "none" || record.stderr === "streamed") &&
    (record.pty === "none" || record.pty === "best-effort" || record.pty === "pty-recorded")
  );
}

function isStepCaptureStatus(value: unknown): value is StepCaptureStatus {
  const record = toRecord(value);
  if (!record) {
    return false;
  }
  return (
    (record.interactive_transcript === undefined || isWitnessCompletenessStatus(record.interactive_transcript)) &&
    (record.stdout === undefined || isWitnessCompletenessStatus(record.stdout)) &&
    (record.stderr === undefined || isWitnessCompletenessStatus(record.stderr)) &&
    (record.pty === undefined || isWitnessCompletenessStatus(record.pty))
  );
}

export function isExecutionStep(value: unknown): value is ExecutionStep {
  const step = toRecord(value);
  if (!step) {
    return false;
  }
  const artifactIds = Array.isArray(step.artifact_ids)
    ? step.artifact_ids
    : Array.isArray(step.artifact_refs)
      ? step.artifact_refs
      : undefined;
  return (
    isString(step.step_id) &&
    isString(step.name) &&
    isString(step.started_at) &&
    (step.ended_at === undefined || isString(step.ended_at)) &&
    (step.exit_code === undefined || isNumber(step.exit_code)) &&
    (step.stdout_hash === undefined || isString(step.stdout_hash)) &&
    (step.stderr_hash === undefined || isString(step.stderr_hash)) &&
    isStringArray(artifactIds) &&
    isNumber(step.retry_count) &&
    isStepStatus(step.status) &&
    (step.capture_status === undefined || isStepCaptureStatus(step.capture_status)) &&
    (step.error === undefined || isString(step.error))
  );
}

export function isDeclarationReceipt(value: unknown): value is DeclarationReceipt {
  const receipt = toRecord(value);
  if (!receipt) {
    return false;
  }
  return (
    isString(receipt.run_id) &&
    isString(receipt.runbook) &&
    isString(receipt.target) &&
    isString(receipt.version) &&
    isString(receipt.entrypoint) &&
    isStringArray(receipt.cli_args) &&
    Array.isArray(receipt.env_vars) &&
    isString(receipt.declared_at)
  );
}

export function isEnvironmentReceipt(value: unknown): value is EnvironmentReceipt {
  const receipt = toRecord(value);
  if (!receipt) {
    return false;
  }
  return (
    isString(receipt.cloud_provider) &&
    typeof receipt.runtimes === "object" &&
    receipt.runtimes !== null &&
    isStringArray(receipt.installed_binaries) &&
    isString(receipt.captured_at)
  );
}

export function isTerminationReceipt(value: unknown): value is TerminationReceipt {
  const receipt = toRecord(value);
  if (!receipt) {
    return false;
  }
  return (
    isRunStatus(receipt.status) &&
    typeof receipt.cleanup_attempted === "boolean" &&
    (receipt.cleanup_succeeded === null || typeof receipt.cleanup_succeeded === "boolean") &&
    Array.isArray(receipt.surviving_resources) &&
    isNumber(receipt.final_exit_code) &&
    isString(receipt.final_digest) &&
    isString(receipt.finished_at)
  );
}
