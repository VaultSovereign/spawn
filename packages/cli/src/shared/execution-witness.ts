import type {
  ArtifactCategory,
  ArtifactRecord,
  ArtifactType,
  AttestationPolicy,
  CaptureModeReceipt,
  DeclarationReceipt,
  EnvironmentReceipt,
  ExecutionRecord,
  ExecutionStep,
  RunStatus,
  StepCaptureStatus,
  StepStatus,
  TerminationReceipt,
  TranscriptCaptureMode,
  TranscriptPolicy,
  TrustPolicy,
  WitnessCompleteness,
  WitnessCompletenessStatus,
} from "@openrouter/spawn-shared";

import { createHash, randomBytes } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  getErrorMessage,
  isArtifactRecord,
  isDeclarationReceipt,
  isEnvironmentReceipt,
  isExecutionRecord,
  isString,
  isTerminationReceipt,
  tryCatch,
} from "@openrouter/spawn-shared";
import pkg from "../../package.json" with { type: "json" };

interface WitnessOptions {
  runbook: string;
  target: string;
  version?: string;
  envVarNames: string[];
  witnessLevel?: string;
  expectedArtifacts?: string[];
  requiredArtifacts?: string[];
  transcriptPolicy?: TranscriptPolicy;
  transcriptCaptureMode?: TranscriptCaptureMode;
  attestationPolicy?: AttestationPolicy;
  trustPolicy?: TrustPolicy;
  trustedSigners?: string[];
}

interface FinalizeWitnessOptions {
  status: RunStatus;
  finalExitCode: number;
  cleanupAttempted: boolean;
  cleanupSucceeded: boolean | null;
  survivingResources: Array<Record<string, string>>;
}

export interface VerifyResult {
  ok: boolean;
  verified: boolean;
  runId: string;
  runDir: string;
  digest?: string;
  checkedFiles: string[];
  errors: string[];
  integrity: {
    ok: boolean;
    schemas: boolean;
    artifacts: boolean;
    checksums: boolean;
    record_digest: boolean;
  };
  capture: {
    ok: boolean;
    interactive_transcript: WitnessCompletenessStatus;
    expected_by_policy: boolean;
    artifact_present: boolean;
    mode: CaptureModeReceipt["interactive_transcript"] | "unknown";
  };
  policy: {
    ok: boolean;
    transcript_policy: TranscriptPolicy;
    attestation_policy: AttestationPolicy;
    trust_policy: TrustPolicy;
    required_artifacts: string[];
    missing_artifacts: string[];
    trusted_signers: string[];
  };
  attestation: {
    ok: boolean;
    state: "none" | "present-unverified" | "verified";
    subject: "record_digest";
    key_id?: string;
    signer_identity_hint?: string;
    cryptographic_valid?: boolean;
    reason?: string;
  };
  trust: {
    ok: boolean;
    state: "none" | "unknown" | "trusted" | "revoked" | "expired" | "disallowed";
    key_id?: string;
    label?: string;
    scope?: string;
    reason?: string;
  };
  transport: {
    kind: "run-directory" | "bundle";
    ok: boolean;
    bundle_digest?: string;
    record_digest?: string;
    record_digest_matches?: boolean;
    bundle_manifest?: boolean;
  };
}

interface StepHandle {
  stepId: string;
  name: string;
  startedAt: string;
}

const CLI_PACKAGE_DIR = fileURLToPath(new URL("../../", import.meta.url));
const DIGEST_RELATIVE_PATHS = [
  "declare.json",
  "environment.json",
  "manifest.lock.json",
  "steps.jsonl",
  "stdout/cli.log",
  "stderr/cli.log",
  "outputs/interactive-transcript.txt",
  "outputs/session-summary.json",
  "outputs/terminal-capture-meta.json",
] as const;

function sha256OfString(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function sha256OfFile(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function writeJson(filePath: string, data: unknown): void {
  mkdirSync(dirname(filePath), {
    recursive: true,
  });
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", {
    mode: 0o600,
  });
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(",")}}`;
}

function findRepoRoot(): string | null {
  let current = resolve(CLI_PACKAGE_DIR, "..", "..");
  while (true) {
    if (existsSync(join(current, "manifest.json")) && existsSync(join(current, "package.json"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

function toPortablePath(filePath: string, preferredBase?: string): string {
  const resolvedPath = resolve(filePath);
  const normalizedPath = resolvedPath.replaceAll("\\", "/");
  const candidateBases = [
    preferredBase,
    process.cwd(),
    process.env.HOME || homedir(),
  ].filter((value): value is string => Boolean(value));

  for (const base of candidateBases) {
    const resolvedBase = resolve(base);
    const normalizedBase = resolvedBase.replaceAll("\\", "/");
    if (normalizedPath === normalizedBase) {
      return ".";
    }
    if (normalizedPath.startsWith(`${normalizedBase}/`)) {
      return relative(resolvedBase, resolvedPath).replaceAll("\\", "/");
    }
  }

  return resolvedPath.replaceAll("\\", "/").split("/").pop() || resolvedPath.replaceAll("\\", "/");
}

function readCommandOutput(args: string[]): string | undefined {
  const result = Bun.spawnSync(args, {
    stdio: [
      "ignore",
      "pipe",
      "ignore",
    ],
  });
  if (result.exitCode !== 0) {
    return undefined;
  }
  const output = new TextDecoder().decode(result.stdout).trim();
  return output || undefined;
}

function detectOperator(): DeclarationReceipt["operator"] {
  const username = process.env.USER || process.env.USERNAME;
  const hostname = process.env.HOSTNAME || process.env.COMPUTERNAME;
  const gitName = readCommandOutput([
    "git",
    "config",
    "--global",
    "user.name",
  ]);
  const gitEmail = readCommandOutput([
    "git",
    "config",
    "--global",
    "user.email",
  ]);

  if (!username && !hostname && !gitName && !gitEmail) {
    return undefined;
  }

  return {
    username,
    hostname,
    git_name: gitName,
    git_email: gitEmail,
  };
}

function collectInstalledBinaries(): string[] {
  const known = [
    "bun",
    "node",
    "git",
    "ssh",
    "gh",
    "gcloud",
    "aws",
    "doctl",
    "hcloud",
    "sprite",
  ];
  return known.filter((binary) => Bun.which(binary) !== null);
}

function readRuntimeVersions(): Record<string, string> {
  const runtimes: Record<string, string> = {};
  if (process.versions.bun) {
    runtimes.bun = process.versions.bun;
  }
  if (process.versions.node) {
    runtimes.node = process.versions.node;
  }
  return runtimes;
}

function resolveRegion(target: string): string | undefined {
  const regionEnvByTarget: Record<string, string[]> = {
    aws: [
      "AWS_DEFAULT_REGION",
    ],
    digitalocean: [
      "DO_REGION",
    ],
    gcp: [
      "GCP_ZONE",
    ],
    hetzner: [
      "HETZNER_LOCATION",
    ],
  };
  return regionEnvByTarget[target]?.map((name) => process.env[name]).find(Boolean);
}

function resolveInstanceType(target: string): string | undefined {
  const typeEnvByTarget: Record<string, string[]> = {
    aws: [
      "LIGHTSAIL_BUNDLE",
    ],
    digitalocean: [
      "DO_DROPLET_SIZE",
    ],
    gcp: [
      "GCP_MACHINE_TYPE",
    ],
    hetzner: [
      "HETZNER_SERVER_TYPE",
    ],
  };
  return typeEnvByTarget[target]?.map((name) => process.env[name]).find(Boolean);
}

function createRunId(): string {
  return `spn_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`;
}

function resolveWitnessSpawnDir(): string {
  const spawnHome = process.env.SPAWN_HOME;
  if (!spawnHome) {
    return join(process.env.HOME || homedir(), ".spawn");
  }

  const resolved = resolve(spawnHome);
  const home = resolve(process.env.HOME || homedir());
  const normalizedResolved = resolved.replaceAll("\\", "/");
  const normalizedHome = home.replaceAll("\\", "/");
  if (normalizedResolved === normalizedHome || normalizedResolved.startsWith(`${normalizedHome}/`)) {
    return resolved;
  }
  throw new Error(`SPAWN_HOME must be within your home directory.\nGot: ${resolved}\nHome: ${home}`);
}

function resolveWitnessRunDir(runId: string): string {
  return join(resolveWitnessSpawnDir(), "runs", runId);
}

export function getExecutionRunDir(runId: string): string {
  return resolveWitnessRunDir(runId);
}

function readUtf8IfExists(filePath: string): string {
  return existsSync(filePath) ? readFileSync(filePath, "utf-8") : "";
}

function resolveDigestFiles(runDir: string): string[] {
  return DIGEST_RELATIVE_PATHS.map((relPath) => join(runDir, relPath)).filter((filePath) => existsSync(filePath));
}

function computeFinalDigest(runDir: string): string {
  const digestLines = resolveDigestFiles(runDir)
    .map((filePath) => `${sha256OfFile(filePath)}  ${relative(runDir, filePath).replaceAll("\\", "/")}`)
    .sort();
  return sha256OfString(digestLines.join("\n"));
}

function parseChecksums(contents: string): Array<{
  hash: string;
  path: string;
}> {
  return contents
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      const match = line.match(/^([a-f0-9]{64})\s{2}(.+)$/);
      return match
        ? [
            {
              hash: match[1],
              path: match[2],
            },
          ]
        : [];
    });
}

function transcriptCompletenessForMode(mode: TranscriptCaptureMode): WitnessCompletenessStatus {
  return mode === "none" ? "absent" : "partial";
}

function defaultCaptureMode(mode: TranscriptCaptureMode): CaptureModeReceipt {
  return {
    interactive_transcript: mode,
    stdout: "streamed",
    stderr: "streamed",
    pty: mode === "none" ? "none" : mode === "pty-recorded" ? "pty-recorded" : "best-effort",
  };
}

export class ExecutionWitness {
  readonly runId: string;
  readonly runDir: string;

  private readonly declarePath: string;
  private readonly environmentPath: string;
  private readonly stepsPath: string;
  private readonly artifactsPath: string;
  private readonly resultPath: string;
  private readonly envelopePath: string;
  private readonly checksumsPath: string;
  private readonly manifestLockPath: string;
  private readonly stdoutPath: string;
  private readonly stderrPath: string;
  private readonly interactiveTranscriptPath: string;
  private readonly sessionSummaryPath: string;
  private readonly terminalCaptureMetaPath: string;
  private readonly expectedArtifacts: string[];
  private readonly requiredArtifacts: string[];
  private readonly transcriptPolicy: TranscriptPolicy;
  private readonly attestationPolicy: AttestationPolicy;
  private readonly trustPolicy: TrustPolicy;
  private readonly trustedSigners: string[];
  private readonly declaration: DeclarationReceipt;
  private readonly hashes: Record<string, string> = {};
  private readonly steps: ExecutionStep[] = [];
  private readonly artifacts: ArtifactRecord[] = [];
  private readonly artifactIdsByLogicalName = new Map<string, string>();
  private readonly startedAt: string;
  private readonly captureMode: CaptureModeReceipt;
  private readonly witnessCompleteness: WitnessCompleteness;
  private environment: EnvironmentReceipt;
  private result: TerminationReceipt | null = null;
  private stdoutWrite?: typeof process.stdout.write;
  private stderrWrite?: typeof process.stderr.write;
  private captureActive = false;

  constructor(private readonly options: WitnessOptions) {
    this.runId = createRunId();
    this.runDir = resolveWitnessRunDir(this.runId);
    this.declarePath = join(this.runDir, "declare.json");
    this.environmentPath = join(this.runDir, "environment.json");
    this.stepsPath = join(this.runDir, "steps.jsonl");
    this.artifactsPath = join(this.runDir, "artifacts.json");
    this.resultPath = join(this.runDir, "result.json");
    this.envelopePath = join(this.runDir, "envelope.json");
    this.checksumsPath = join(this.runDir, "checksums.txt");
    this.manifestLockPath = join(this.runDir, "manifest.lock.json");
    this.stdoutPath = join(this.runDir, "stdout", "cli.log");
    this.stderrPath = join(this.runDir, "stderr", "cli.log");
    this.interactiveTranscriptPath = join(this.runDir, "outputs", "interactive-transcript.txt");
    this.sessionSummaryPath = join(this.runDir, "outputs", "session-summary.json");
    this.terminalCaptureMetaPath = join(this.runDir, "outputs", "terminal-capture-meta.json");
    this.expectedArtifacts = options.expectedArtifacts ?? [];
    this.requiredArtifacts = options.requiredArtifacts ?? [];
    this.transcriptPolicy = options.transcriptPolicy ?? "optional";
    this.attestationPolicy = options.attestationPolicy ?? "optional";
    this.trustPolicy = options.trustPolicy ?? "any-valid";
    this.trustedSigners = options.trustedSigners ?? [];
    this.captureMode = defaultCaptureMode(options.transcriptCaptureMode ?? "best-effort");
    this.witnessCompleteness = {
      declare: "complete",
      environment: "complete",
      step_ledger: "complete",
      artifact_manifest: "complete",
      integrity_manifest: "absent",
      interactive_transcript: transcriptCompletenessForMode(this.captureMode.interactive_transcript),
    };
    this.startedAt = new Date().toISOString();

    mkdirSync(join(this.runDir, "stdout"), {
      recursive: true,
    });
    mkdirSync(join(this.runDir, "stderr"), {
      recursive: true,
    });
    mkdirSync(join(this.runDir, "outputs"), {
      recursive: true,
    });
    writeFileSync(this.stdoutPath, "", {
      mode: 0o600,
    });
    writeFileSync(this.stderrPath, "", {
      mode: 0o600,
    });
    writeFileSync(this.stepsPath, "", {
      mode: 0o600,
    });
    if (this.captureMode.interactive_transcript !== "none") {
      writeFileSync(this.interactiveTranscriptPath, "", {
        mode: 0o600,
      });
    }

    const repoRoot = findRepoRoot();
    const entrypoint = `sh/${options.target}/${options.runbook}.sh`;
    const resolvedEntrypoint =
      repoRoot && existsSync(join(repoRoot, entrypoint))
        ? toPortablePath(join(repoRoot, entrypoint), repoRoot)
        : undefined;
    const manifestPath =
      repoRoot && existsSync(join(repoRoot, "manifest.json"))
        ? toPortablePath(join(repoRoot, "manifest.json"), repoRoot)
        : undefined;
    const manifestSha =
      repoRoot && existsSync(join(repoRoot, "manifest.json"))
        ? sha256OfFile(join(repoRoot, "manifest.json"))
        : undefined;
    const configPath = process.env.SPAWN_CONFIG_PATH ? resolve(process.env.SPAWN_CONFIG_PATH) : undefined;
    const configSha = configPath && existsSync(configPath) ? sha256OfFile(configPath) : undefined;
    const spawnCommit =
      repoRoot && existsSync(join(repoRoot, ".git"))
        ? readCommandOutput([
            "git",
            "-C",
            repoRoot,
            "rev-parse",
            "HEAD",
          ])
        : undefined;

    const manifestLock = {
      run_id: this.runId,
      runbook: options.runbook,
      target: options.target,
      entrypoint,
      resolved_entrypoint: resolvedEntrypoint,
      manifest_path: manifestPath,
      manifest_sha256: manifestSha,
      expected_artifacts: this.expectedArtifacts,
      required_artifacts: this.requiredArtifacts,
      transcript_policy: this.transcriptPolicy,
      attestation_policy: this.attestationPolicy,
      trust_policy: this.trustPolicy,
      trusted_signers: this.trustedSigners,
      capture_mode: this.captureMode.interactive_transcript,
      witness_level: options.witnessLevel ?? "standard",
    };
    writeJson(this.manifestLockPath, manifestLock);

    this.declaration = {
      run_id: this.runId,
      runbook: options.runbook,
      target: options.target,
      version: options.version ?? `spawn-cli@${pkg.version}`,
      entrypoint,
      ...(resolvedEntrypoint
        ? {
            resolved_entrypoint: resolvedEntrypoint,
          }
        : {}),
      ...(spawnCommit
        ? {
            spawn_commit: spawnCommit,
          }
        : {}),
      ...(manifestSha
        ? {
            manifest_sha256: manifestSha,
          }
        : {}),
      ...(configPath
        ? {
            config_path: toPortablePath(configPath),
          }
        : {}),
      ...(configSha
        ? {
            config_sha256: configSha,
          }
        : {}),
      cli_args: process.argv.slice(2),
      env_vars: Array.from(new Set(options.envVarNames))
        .sort()
        .map((name) => ({
          name,
          present: Boolean(process.env[name]),
        })),
      operator: detectOperator(),
      declared_at: this.startedAt,
    };
    writeJson(this.declarePath, this.declaration);

    this.environment = {
      cloud_provider: options.target,
      region: resolveRegion(options.target),
      instance_type: resolveInstanceType(options.target),
      os: `${process.platform}/${process.arch}`,
      runtimes: readRuntimeVersions(),
      installed_binaries: collectInstalledBinaries(),
      captured_at: this.startedAt,
    };
    writeJson(this.environmentPath, this.environment);

    this.writeTerminalCaptureMeta();
    this.writeSessionSummary();

    this.refreshArtifact(
      "declaration-receipt",
      this.declarePath,
      "application/json",
      "declare",
      "receipt",
      "declaration-receipt",
    );
    this.refreshArtifact(
      "environment-receipt",
      this.environmentPath,
      "application/json",
      "environment",
      "receipt",
      "environment-receipt",
    );
    this.refreshArtifact(
      "manifest-lock",
      this.manifestLockPath,
      "application/json",
      "declare",
      "receipt",
      "manifest-lock",
    );
    this.refreshArtifact("step-ledger", this.stepsPath, "application/x-ndjson", "execute", "receipt", "step-ledger");
    this.refreshArtifact("stdout-transcript", this.stdoutPath, "text/plain", "execute", "log", "stdout-transcript");
    this.refreshArtifact("stderr-transcript", this.stderrPath, "text/plain", "execute", "log", "stderr-transcript");
    if (this.captureMode.interactive_transcript !== "none") {
      this.refreshArtifact(
        "interactive-transcript",
        this.interactiveTranscriptPath,
        "text/plain",
        "execute",
        "log",
        "interactive-transcript",
      );
    }
    this.refreshArtifact(
      "terminal-capture-meta",
      this.terminalCaptureMetaPath,
      "application/json",
      "witness",
      "receipt",
      "terminal-capture-meta",
    );
    this.refreshArtifact(
      "session-summary",
      this.sessionSummaryPath,
      "application/json",
      "seal",
      "output",
      "session-summary",
    );
    this.persistArtifacts();
    this.writeEnvelope();
  }

  startOutputCapture(): void {
    if (this.captureActive) {
      return;
    }
    this.captureActive = true;
    this.stdoutWrite = process.stdout.write.bind(process.stdout);
    this.stderrWrite = process.stderr.write.bind(process.stderr);

    const stdoutProxy: typeof process.stdout.write = (chunk, encoding, cb) => {
      appendFileSync(this.stdoutPath, isString(chunk) ? chunk : Buffer.from(chunk));
      return Reflect.apply(this.stdoutWrite!, process.stdout, [
        chunk,
        encoding,
        cb,
      ]);
    };
    const stderrProxy: typeof process.stderr.write = (chunk, encoding, cb) => {
      appendFileSync(this.stderrPath, isString(chunk) ? chunk : Buffer.from(chunk));
      return Reflect.apply(this.stderrWrite!, process.stderr, [
        chunk,
        encoding,
        cb,
      ]);
    };
    process.stdout.write = stdoutProxy;
    process.stderr.write = stderrProxy;
  }

  stopOutputCapture(): void {
    if (!this.captureActive) {
      return;
    }
    if (this.stdoutWrite) {
      process.stdout.write = this.stdoutWrite;
    }
    if (this.stderrWrite) {
      process.stderr.write = this.stderrWrite;
    }
    this.captureActive = false;
  }

  beginStep(name: string): StepHandle {
    return {
      stepId: `step_${String(this.steps.length + 1).padStart(4, "0")}`,
      name,
      startedAt: new Date().toISOString(),
    };
  }

  endStep(
    handle: StepHandle,
    status: StepStatus,
    opts: {
      exitCode?: number;
      retryCount?: number;
      error?: string;
      artifactIds?: string[];
      stdoutHash?: string;
      stderrHash?: string;
      captureStatus?: StepCaptureStatus;
    } = {},
  ): ExecutionStep {
    const step: ExecutionStep = {
      step_id: handle.stepId,
      name: handle.name,
      started_at: handle.startedAt,
      ended_at: new Date().toISOString(),
      exit_code: opts.exitCode,
      stdout_hash: opts.stdoutHash ?? this.tryHashFile(this.stdoutPath),
      stderr_hash: opts.stderrHash ?? this.tryHashFile(this.stderrPath),
      artifact_ids: opts.artifactIds ?? this.defaultArtifactIdsForStep(handle.name),
      retry_count: opts.retryCount ?? 0,
      status,
      ...((opts.captureStatus ?? this.defaultCaptureStatusForStep(handle.name))
        ? {
            capture_status: opts.captureStatus ?? this.defaultCaptureStatusForStep(handle.name),
          }
        : {}),
      ...(opts.error
        ? {
            error: opts.error,
          }
        : {}),
    };
    this.steps.push(step);
    writeFileSync(this.stepsPath, JSON.stringify(step) + "\n", {
      flag: "a",
      mode: 0o600,
    });
    this.refreshArtifact("step-ledger", this.stepsPath, "application/x-ndjson", "execute", "receipt", "step-ledger");
    this.persistArtifacts();
    this.writeEnvelope();
    return step;
  }

  updateEnvironment(values: Partial<EnvironmentReceipt>): void {
    this.environment = {
      ...this.environment,
      ...values,
      runtimes: {
        ...this.environment.runtimes,
        ...(values.runtimes ?? {}),
      },
      installed_binaries: values.installed_binaries ?? this.environment.installed_binaries,
      captured_at: new Date().toISOString(),
    };
    writeJson(this.environmentPath, this.environment);
    this.refreshArtifact(
      "environment-receipt",
      this.environmentPath,
      "application/json",
      "environment",
      "receipt",
      "environment-receipt",
    );
    this.persistArtifacts();
    this.writeEnvelope();
  }

  finalize(opts: FinalizeWitnessOptions): ExecutionRecord {
    this.stopOutputCapture();
    this.refreshArtifact("stdout-transcript", this.stdoutPath, "text/plain", "execute", "log", "stdout-transcript");
    this.refreshArtifact("stderr-transcript", this.stderrPath, "text/plain", "execute", "log", "stderr-transcript");

    if (this.captureMode.interactive_transcript !== "none") {
      const transcriptSections: string[] = [];
      const stdoutContent = readUtf8IfExists(this.stdoutPath).trim();
      const stderrContent = readUtf8IfExists(this.stderrPath).trim();
      if (stdoutContent) {
        transcriptSections.push(`=== stdout ===\n${stdoutContent}`);
      }
      if (stderrContent) {
        transcriptSections.push(`=== stderr ===\n${stderrContent}`);
      }
      writeFileSync(
        this.interactiveTranscriptPath,
        transcriptSections.length > 0 ? transcriptSections.join("\n\n") + "\n" : "",
        {
          mode: 0o600,
        },
      );
      this.witnessCompleteness.interactive_transcript = "partial";
      this.refreshArtifact(
        "interactive-transcript",
        this.interactiveTranscriptPath,
        "text/plain",
        "execute",
        "log",
        "interactive-transcript",
      );
    }

    this.witnessCompleteness.integrity_manifest = "complete";
    this.writeTerminalCaptureMeta();
    this.writeSessionSummary();
    this.refreshArtifact(
      "terminal-capture-meta",
      this.terminalCaptureMetaPath,
      "application/json",
      "witness",
      "receipt",
      "terminal-capture-meta",
    );
    this.refreshArtifact(
      "session-summary",
      this.sessionSummaryPath,
      "application/json",
      "seal",
      "output",
      "session-summary",
    );
    this.persistArtifacts();

    const finalDigest = computeFinalDigest(this.runDir);

    this.result = {
      status: opts.status,
      cleanup_attempted: opts.cleanupAttempted,
      cleanup_succeeded: opts.cleanupSucceeded,
      surviving_resources: opts.survivingResources,
      final_exit_code: opts.finalExitCode,
      final_digest: finalDigest,
      finished_at: new Date().toISOString(),
    };
    writeJson(this.resultPath, this.result);

    this.refreshArtifact(
      "termination-receipt",
      this.resultPath,
      "application/json",
      "seal",
      "receipt",
      "termination-receipt",
    );
    this.persistArtifacts();

    const checksumFiles = [
      ...resolveDigestFiles(this.runDir),
      this.resultPath,
    ];
    const checksumLines = checksumFiles
      .map((filePath) => {
        const rel = relative(this.runDir, filePath).replaceAll("\\", "/");
        const hash = sha256OfFile(filePath);
        this.hashes[rel] = hash;
        return `${hash}  ${rel}`;
      })
      .sort();
    writeFileSync(this.checksumsPath, checksumLines.join("\n") + "\n", {
      mode: 0o600,
    });

    this.refreshArtifact(
      "integrity-manifest",
      this.checksumsPath,
      "text/plain",
      "seal",
      "receipt",
      "integrity-manifest",
    );
    this.persistArtifacts();

    this.hashes["artifacts.json"] = sha256OfFile(this.artifactsPath);
    this.hashes["result.json"] = sha256OfFile(this.resultPath);
    this.hashes["checksums.txt"] = sha256OfFile(this.checksumsPath);
    this.hashes["steps.jsonl"] = sha256OfFile(this.stepsPath);
    this.hashes["outputs/session-summary.json"] = sha256OfFile(this.sessionSummaryPath);
    this.hashes["outputs/terminal-capture-meta.json"] = sha256OfFile(this.terminalCaptureMetaPath);
    if (existsSync(this.interactiveTranscriptPath)) {
      this.hashes["outputs/interactive-transcript.txt"] = sha256OfFile(this.interactiveTranscriptPath);
    }

    const record = this.writeEnvelope();
    return record;
  }

  private tryHashFile(filePath: string): string | undefined {
    return existsSync(filePath) ? sha256OfFile(filePath) : undefined;
  }

  private writeTerminalCaptureMeta(): void {
    writeJson(this.terminalCaptureMetaPath, {
      run_id: this.runId,
      runbook: this.options.runbook,
      target: this.options.target,
      transport: this.options.target === "local" ? "local-shell" : "remote-shell",
      pty: {
        mode: this.captureMode.pty,
        attempted: this.captureMode.pty !== "none",
      },
      stdout: {
        mode: this.captureMode.stdout,
        path: relative(this.runDir, this.stdoutPath).replaceAll("\\", "/"),
      },
      stderr: {
        mode: this.captureMode.stderr,
        path: relative(this.runDir, this.stderrPath).replaceAll("\\", "/"),
      },
      interactive_transcript: {
        mode: this.captureMode.interactive_transcript,
        completeness: this.witnessCompleteness.interactive_transcript,
        path:
          this.captureMode.interactive_transcript === "none"
            ? undefined
            : relative(this.runDir, this.interactiveTranscriptPath).replaceAll("\\", "/"),
      },
      degradation_flags:
        this.captureMode.interactive_transcript === "none"
          ? [
              "interactive-transcript-disabled",
            ]
          : [
              "interactive-transcript-best-effort",
            ],
      captured_at: new Date().toISOString(),
    });
  }

  private writeSessionSummary(): void {
    writeJson(this.sessionSummaryPath, {
      run_id: this.runId,
      runbook: this.options.runbook,
      target: this.options.target,
      transcript_policy: this.transcriptPolicy,
      attestation_policy: this.attestationPolicy,
      trust_policy: this.trustPolicy,
      capture_mode: this.captureMode,
      witness_completeness: this.witnessCompleteness,
      transcript_artifact_id:
        this.captureMode.interactive_transcript === "none"
          ? undefined
          : this.ensureArtifactId("interactive-transcript"),
      stdout_artifact_id: this.ensureArtifactId("stdout-transcript"),
      stderr_artifact_id: this.ensureArtifactId("stderr-transcript"),
      required_artifacts: this.requiredArtifacts,
      expected_artifacts: this.expectedArtifacts,
      trusted_signers: this.trustedSigners,
      finalized: this.result !== null || this.witnessCompleteness.integrity_manifest === "complete",
      summarized_at: new Date().toISOString(),
    });
  }

  private defaultArtifactIdsForStep(stepName: string): string[] {
    if (stepName !== "interactive-session") {
      return [];
    }
    const ids = [
      this.ensureArtifactId("stdout-transcript"),
      this.ensureArtifactId("stderr-transcript"),
      this.ensureArtifactId("terminal-capture-meta"),
      this.ensureArtifactId("session-summary"),
    ];
    if (this.captureMode.interactive_transcript !== "none") {
      ids.push(this.ensureArtifactId("interactive-transcript"));
    }
    return ids;
  }

  private defaultCaptureStatusForStep(stepName: string): StepCaptureStatus | undefined {
    if (stepName !== "interactive-session") {
      return undefined;
    }
    return {
      interactive_transcript: this.witnessCompleteness.interactive_transcript,
      stdout: "complete",
      stderr: "complete",
      pty: this.captureMode.pty === "none" ? "absent" : "partial",
    };
  }

  private ensureArtifactId(logicalName: string): string {
    const existing = this.artifactIdsByLogicalName.get(logicalName);
    if (existing) {
      return existing;
    }
    const artifactId = `a${String(this.artifactIdsByLogicalName.size + 1).padStart(4, "0")}`;
    this.artifactIdsByLogicalName.set(logicalName, artifactId);
    return artifactId;
  }

  private refreshArtifact(
    logicalName: string,
    filePath: string,
    mediaType: string,
    provenanceStep: string,
    category: ArtifactCategory,
    artifactType: ArtifactType,
  ): void {
    if (!existsSync(filePath)) {
      return;
    }
    const record: ArtifactRecord = {
      artifact_id: this.ensureArtifactId(logicalName),
      logical_name: logicalName,
      path: relative(this.runDir, filePath).replaceAll("\\", "/"),
      media_type: mediaType,
      byte_size: statSync(filePath).size,
      sha256: sha256OfFile(filePath),
      provenance_step: provenanceStep,
      category,
      artifact_type: artifactType,
    };
    const existingIdx = this.artifacts.findIndex((artifact) => artifact.artifact_id === record.artifact_id);
    if (existingIdx >= 0) {
      this.artifacts[existingIdx] = record;
    } else {
      this.artifacts.push(record);
    }
  }

  private persistArtifacts(): void {
    writeJson(this.artifactsPath, this.artifacts);
  }

  private writeEnvelope(): ExecutionRecord {
    this.hashes["declare.json"] = sha256OfFile(this.declarePath);
    this.hashes["environment.json"] = sha256OfFile(this.environmentPath);
    this.hashes["manifest.lock.json"] = sha256OfFile(this.manifestLockPath);
    this.hashes["stdout/cli.log"] = sha256OfFile(this.stdoutPath);
    this.hashes["stderr/cli.log"] = sha256OfFile(this.stderrPath);
    this.hashes["artifacts.json"] = sha256OfFile(this.artifactsPath);
    const record: ExecutionRecord = {
      run_id: this.runId,
      runbook: this.options.runbook,
      target: this.options.target,
      version: this.options.version ?? `spawn-cli@${pkg.version}`,
      inputs: {
        cli_args: this.declaration.cli_args,
        config_path: this.declaration.config_path,
        config_sha256: this.declaration.config_sha256,
        env_var_names: this.declaration.env_vars.map((entry) => entry.name),
      },
      environment: this.environment,
      steps: this.steps,
      artifacts: this.artifacts,
      result: this.result,
      witness_completeness: this.witnessCompleteness,
      capture_mode: this.captureMode,
      policy: {
        transcript_policy: this.transcriptPolicy,
        attestation_policy: this.attestationPolicy,
        trust_policy: this.trustPolicy,
        required_artifacts: this.requiredArtifacts,
        expected_artifacts: this.expectedArtifacts,
        trusted_signers: this.trustedSigners,
      },
      timestamps: {
        declared_at: this.declaration.declared_at,
        started_at: this.startedAt,
        ...(this.result
          ? {
              ended_at: this.result.finished_at,
            }
          : {}),
      },
      hashes: this.hashes,
      witness: {
        witness_level: this.options.witnessLevel ?? "standard",
        tool: `spawn-cli@${pkg.version}`,
        declaration: this.declaration,
        trust_capability: {
          verifier: "local-key-registry/v1",
          trust_store: "unknown",
        },
      },
    };
    this.hashes["envelope.json"] = sha256OfString(stableStringify(record));
    writeJson(this.envelopePath, record);
    return record;
  }
}

export function createExecutionWitness(options: WitnessOptions): ExecutionWitness {
  return new ExecutionWitness(options);
}

export function verifyExecutionDirectory(runDir: string, runId = ""): VerifyResult {
  const checkedFiles: string[] = [];
  const errors: string[] = [];
  const integrity = {
    ok: false,
    schemas: false,
    artifacts: false,
    checksums: false,
    record_digest: false,
  };

  if (!existsSync(runDir)) {
    return {
      ok: false,
      verified: false,
      runId,
      runDir,
      checkedFiles,
      errors: [
        `Run directory not found: ${runDir}`,
      ],
      integrity,
      capture: {
        ok: false,
        interactive_transcript: "absent",
        expected_by_policy: false,
        artifact_present: false,
        mode: "unknown",
      },
      policy: {
        ok: false,
        transcript_policy: "optional",
        attestation_policy: "optional",
        trust_policy: "any-valid",
        required_artifacts: [],
        missing_artifacts: [],
        trusted_signers: [],
      },
      attestation: {
        ok: true,
        state: "none",
        subject: "record_digest",
      },
      trust: {
        ok: true,
        state: "none",
      },
      transport: {
        kind: "run-directory",
        ok: false,
      },
    };
  }

  const envelopePath = join(runDir, "envelope.json");
  const declarePath = join(runDir, "declare.json");
  const environmentPath = join(runDir, "environment.json");
  const artifactsPath = join(runDir, "artifacts.json");
  const resultPath = join(runDir, "result.json");

  let envelope: unknown;
  let declaration: unknown;
  let environment: unknown;
  let artifacts: unknown;
  let result: unknown;

  const loadResult = tryCatch(() => {
    envelope = JSON.parse(readFileSync(envelopePath, "utf-8"));
    declaration = JSON.parse(readFileSync(declarePath, "utf-8"));
    environment = JSON.parse(readFileSync(environmentPath, "utf-8"));
    artifacts = JSON.parse(readFileSync(artifactsPath, "utf-8"));
    result = JSON.parse(readFileSync(resultPath, "utf-8"));
  });
  if (!loadResult.ok) {
    return {
      ok: false,
      verified: false,
      runId,
      runDir,
      checkedFiles,
      errors: [
        `Failed to read proof bundle: ${getErrorMessage(loadResult.error)}`,
      ],
      integrity,
      capture: {
        ok: false,
        interactive_transcript: "absent",
        expected_by_policy: false,
        artifact_present: false,
        mode: "unknown",
      },
      policy: {
        ok: false,
        transcript_policy: "optional",
        attestation_policy: "optional",
        trust_policy: "any-valid",
        required_artifacts: [],
        missing_artifacts: [],
        trusted_signers: [],
      },
      attestation: {
        ok: true,
        state: "none",
        subject: "record_digest",
      },
      trust: {
        ok: true,
        state: "none",
      },
      transport: {
        kind: "run-directory",
        ok: false,
      },
    };
  }

  const envelopeOk = isExecutionRecord(envelope);
  const declarationOk = isDeclarationReceipt(declaration);
  const environmentOk = isEnvironmentReceipt(environment);
  const artifactsOk = Array.isArray(artifacts) && artifacts.every(isArtifactRecord);
  const resultOk = isTerminationReceipt(result);

  integrity.schemas = envelopeOk && declarationOk && environmentOk && artifactsOk && resultOk;

  if (!envelopeOk) {
    errors.push("Invalid envelope.json structure");
  }
  if (!declarationOk) {
    errors.push("Invalid declare.json structure");
  }
  if (!environmentOk) {
    errors.push("Invalid environment.json structure");
  }
  if (!artifactsOk) {
    errors.push("Invalid artifacts.json structure");
  }
  if (!resultOk) {
    errors.push("Invalid result.json structure");
  }

  const artifactList = artifactsOk ? artifacts : [];
  let artifactErrors = 0;
  for (const artifact of artifactList) {
    const filePath = join(runDir, artifact.path);
    checkedFiles.push(artifact.path);
    if (!existsSync(filePath)) {
      errors.push(`Missing artifact: ${artifact.path}`);
      artifactErrors += 1;
      continue;
    }
    const actualHash = sha256OfFile(filePath);
    if (actualHash !== artifact.sha256) {
      errors.push(`Artifact hash mismatch: ${artifact.path}`);
      artifactErrors += 1;
    }
  }
  integrity.artifacts = artifactErrors === 0;

  const checksumsPath = join(runDir, "checksums.txt");
  if (!existsSync(checksumsPath)) {
    errors.push("Missing checksums.txt");
  } else {
    checkedFiles.push("checksums.txt");
    const checksumEntries = parseChecksums(readFileSync(checksumsPath, "utf-8"));
    let checksumErrors = 0;
    for (const entry of checksumEntries) {
      const filePath = join(runDir, entry.path);
      checkedFiles.push(entry.path);
      if (!existsSync(filePath)) {
        errors.push(`Checksum target missing: ${entry.path}`);
        checksumErrors += 1;
        continue;
      }
      if (sha256OfFile(filePath) !== entry.hash) {
        errors.push(`Checksum mismatch: ${entry.path}`);
        checksumErrors += 1;
      }
    }
    integrity.checksums = checksumErrors === 0;
  }

  let digest: string | undefined;
  if (resultOk) {
    digest = computeFinalDigest(runDir);
    if (digest !== result.final_digest) {
      errors.push("Final digest mismatch");
    } else {
      integrity.record_digest = true;
    }
  }

  const transcriptPolicy = envelopeOk ? envelope.policy.transcript_policy : "optional";
  const attestationPolicy = envelopeOk ? envelope.policy.attestation_policy : "optional";
  const trustPolicy = envelopeOk ? envelope.policy.trust_policy : "any-valid";
  const requiredArtifacts = envelopeOk ? envelope.policy.required_artifacts : [];
  const trustedSigners = envelopeOk ? envelope.policy.trusted_signers : [];
  const missingArtifacts = requiredArtifacts.filter(
    (logicalName) => !artifactList.some((artifact) => artifact.logical_name === logicalName),
  );
  const transcriptArtifactPresent = artifactList.some(
    (artifact) => artifact.artifact_type === "interactive-transcript",
  );
  const transcriptCompleteness = envelopeOk ? envelope.witness_completeness.interactive_transcript : "absent";
  const transcriptExpected = transcriptPolicy === "required";
  const captureOk = !transcriptExpected || transcriptCompleteness !== "absent";
  const policyOk = captureOk && missingArtifacts.length === 0;

  if (transcriptExpected && transcriptCompleteness === "absent") {
    errors.push("Transcript required by policy but not captured");
  }
  for (const missingArtifact of missingArtifacts) {
    errors.push(`Required artifact missing: ${missingArtifact}`);
  }

  integrity.ok = integrity.schemas && integrity.artifacts && integrity.checksums && integrity.record_digest;
  const verified = integrity.ok && policyOk;

  return {
    ok: verified,
    verified,
    runId,
    runDir,
    digest,
    checkedFiles,
    errors,
    integrity,
    capture: {
      ok: captureOk,
      interactive_transcript: transcriptCompleteness,
      expected_by_policy: transcriptExpected,
      artifact_present: transcriptArtifactPresent,
      mode: envelopeOk ? envelope.capture_mode.interactive_transcript : "unknown",
    },
    policy: {
      ok: policyOk,
      transcript_policy: transcriptPolicy,
      attestation_policy: attestationPolicy,
      trust_policy: trustPolicy,
      required_artifacts: requiredArtifacts,
      missing_artifacts: missingArtifacts,
      trusted_signers: trustedSigners,
    },
    attestation: {
      ok: true,
      state: "none",
      subject: "record_digest",
    },
    trust: {
      ok: true,
      state: "none",
    },
    transport: {
      kind: "run-directory",
      ok: true,
      record_digest: digest,
      record_digest_matches: integrity.record_digest,
    },
  };
}

export function verifyExecutionRun(runId: string): VerifyResult {
  return verifyExecutionDirectory(resolveWitnessRunDir(runId), runId);
}
