import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createExecutionWitness, verifyExecutionRun } from "../shared/execution-witness";

describe("execution witness", () => {
  let testSpawnHome: string;
  let savedSpawnHome: string | undefined;

  beforeEach(() => {
    savedSpawnHome = process.env.SPAWN_HOME;
    const home = (process.env.HOME ?? "").replaceAll("\\", "/");
    testSpawnHome = `${home}/.spawn-test-witness-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    process.env.SPAWN_HOME = testSpawnHome;
  });

  afterEach(() => {
    if (savedSpawnHome !== undefined) {
      process.env.SPAWN_HOME = savedSpawnHome;
    } else {
      delete process.env.SPAWN_HOME;
    }
    rmSync(testSpawnHome, {
      recursive: true,
      force: true,
    });
  });

  it("writes a verifiable proof bundle", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [
        "OPENROUTER_API_KEY",
        "MODEL_ID",
      ],
    });

    witness.startOutputCapture();
    console.log("hello witness");
    console.error("stderr witness");

    const step = witness.beginStep("authenticate-cloud");
    witness.endStep(step, "success", {
      exitCode: 0,
    });
    const sessionStep = witness.beginStep("interactive-session");
    witness.endStep(sessionStep, "success", {
      exitCode: 0,
    });
    witness.updateEnvironment({
      public_ip: "127.0.0.1",
      connection_user: "tester",
    });

    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    expect(record.run_id).toMatch(/^spn_/);
    expect(existsSync(join(testSpawnHome, "runs", record.run_id, "declare.json"))).toBe(true);
    expect(existsSync(join(testSpawnHome, "runs", record.run_id, "checksums.txt"))).toBe(true);
    expect(record.witness_completeness.interactive_transcript).toBe("partial");
    expect(record.capture_mode.interactive_transcript).toBe("best-effort");
    expect(record.steps[1]?.artifact_ids.length).toBeGreaterThan(0);
    expect(record.artifacts.some((artifact) => artifact.artifact_type === "interactive-transcript")).toBe(true);
    expect(record.artifacts.some((artifact) => artifact.artifact_type === "terminal-capture-meta")).toBe(true);

    const verification = verifyExecutionRun(record.run_id);
    expect(verification.ok).toBe(true);
    expect(verification.errors).toHaveLength(0);
    expect(verification.integrity.ok).toBe(true);
    expect(verification.capture.interactive_transcript).toBe("partial");
    expect(verification.policy.ok).toBe(true);
  });

  it("fails verification when a receipt is modified", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [
        "OPENROUTER_API_KEY",
      ],
    });

    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    const declarePath = join(testSpawnHome, "runs", record.run_id, "declare.json");
    const declared = JSON.parse(readFileSync(declarePath, "utf-8"));
    declared.runbook = "tampered";
    writeFileSync(declarePath, JSON.stringify(declared, null, 2) + "\n");

    const verification = verifyExecutionRun(record.run_id);
    expect(verification.ok).toBe(false);
    expect(verification.errors.some((error) => error.includes("Artifact hash mismatch: declare.json"))).toBe(true);
  });

  it("fails verification when transcript policy requires capture but capture is disabled", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [],
      transcriptPolicy: "required",
      transcriptCaptureMode: "none",
    });

    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    expect(record.witness_completeness.interactive_transcript).toBe("absent");
    expect(record.capture_mode.interactive_transcript).toBe("none");

    const verification = verifyExecutionRun(record.run_id);
    expect(verification.ok).toBe(false);
    expect(verification.capture.ok).toBe(false);
    expect(verification.policy.ok).toBe(false);
    expect(verification.errors).toContain("Transcript required by policy but not captured");
  });
});
