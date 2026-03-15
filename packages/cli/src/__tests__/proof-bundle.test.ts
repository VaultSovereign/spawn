import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { createExecutionWitness } from "../shared/execution-witness";
import { exportExecutionBundle, verifyExecutionSource } from "../shared/proof-bundle";

function sha256OfFile(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

describe("proof bundle", () => {
  let testSpawnHome: string;
  let savedSpawnHome: string | undefined;

  beforeEach(() => {
    savedSpawnHome = process.env.SPAWN_HOME;
    const home = (process.env.HOME ?? process.env.USERPROFILE ?? "").replaceAll("\\", "/");
    testSpawnHome = `${home}/.spawn-test-bundle-${Date.now()}-${Math.random().toString(16).slice(2)}`;
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

  it("verifies with the same integrity, capture, and policy semantics from a live run and bundle", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [
        "OPENROUTER_API_KEY",
      ],
    });

    witness.startOutputCapture();
    console.log("bundle stdout");
    console.error("bundle stderr");
    const sessionStep = witness.beginStep("interactive-session");
    witness.endStep(sessionStep, "success", {
      exitCode: 0,
    });

    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    const live = verifyExecutionSource(record.run_id);
    const firstBundle = exportExecutionBundle(record.run_id);
    const firstBundleSha = sha256OfFile(firstBundle.bundlePath);
    const secondBundle = exportExecutionBundle(record.run_id);
    const secondBundleSha = sha256OfFile(secondBundle.bundlePath);
    const bundled = verifyExecutionSource(firstBundle.bundlePath);

    expect(existsSync(firstBundle.bundlePath)).toBe(true);
    expect(firstBundleSha).toBe(secondBundleSha);
    expect(firstBundle.bundleDigest).toBe(secondBundle.bundleDigest);
    expect(live.ok).toBe(true);
    expect(bundled.ok).toBe(true);
    expect(bundled.digest).toBe(live.digest);
    expect(bundled.integrity).toEqual(live.integrity);
    expect(bundled.capture).toEqual(live.capture);
    expect(bundled.policy).toEqual(live.policy);
    expect(bundled.transport.kind).toBe("bundle");
    expect(bundled.transport.bundle_digest).toBe(firstBundle.bundleDigest);
    expect(bundled.transport.record_digest_matches).toBe(true);
  });

  it("preserves policy failure semantics in the exported bundle", () => {
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

    const bundle = exportExecutionBundle(record.run_id);
    const bundled = verifyExecutionSource(bundle.bundlePath);

    expect(bundled.ok).toBe(false);
    expect(bundled.integrity.ok).toBe(true);
    expect(bundled.capture.ok).toBe(false);
    expect(bundled.policy.ok).toBe(false);
    expect(bundled.errors).toContain("Transcript required by policy but not captured");
  });
});
