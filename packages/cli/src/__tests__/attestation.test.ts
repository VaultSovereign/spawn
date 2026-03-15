import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { attestExecutionRun } from "../shared/attestation";
import { createExecutionWitness, getExecutionRunDir } from "../shared/execution-witness";
import { getAttestationVerifierKeyPath } from "../shared/paths";
import { exportExecutionBundle, verifyExecutionSource } from "../shared/proof-bundle";
import { addTrustEntry } from "../shared/trust";

describe("attestation", () => {
  let testSpawnHome: string;
  let savedSpawnHome: string | undefined;

  beforeEach(() => {
    savedSpawnHome = process.env.SPAWN_HOME;
    const home = (process.env.HOME ?? process.env.USERPROFILE ?? "").replaceAll("\\", "/");
    testSpawnHome = `${home}/.spawn-test-attestation-${Date.now()}-${Math.random().toString(16).slice(2)}`;
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

  it("reports no attestation for unsigned runs and bundles", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [],
    });
    const step = witness.beginStep("interactive-session");
    witness.endStep(step, "success", {
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
    const bundle = exportExecutionBundle(record.run_id);
    const bundled = verifyExecutionSource(bundle.bundlePath);

    expect(live.attestation.state).toBe("none");
    expect(live.attestation.ok).toBe(true);
    expect(bundled.attestation.state).toBe("none");
    expect(bundled.attestation.ok).toBe(true);
  });

  it("verifies attestation while leaving signer trust unknown by default", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [],
    });
    const step = witness.beginStep("interactive-session");
    witness.endStep(step, "success", {
      exitCode: 0,
    });
    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    const attestation = attestExecutionRun(getExecutionRunDir(record.run_id));
    const live = verifyExecutionSource(record.run_id);
    const bundle = exportExecutionBundle(record.run_id);
    const bundled = verifyExecutionSource(bundle.bundlePath);

    expect(live.ok).toBe(true);
    expect(live.attestation.state).toBe("verified");
    expect(live.attestation.key_id).toBe(attestation.keyId);
    expect(live.trust.state).toBe("unknown");
    expect(bundled.ok).toBe(true);
    expect(bundled.attestation.state).toBe("verified");
    expect(bundled.attestation.key_id).toBe(attestation.keyId);
    expect(bundled.trust.state).toBe("unknown");
  });

  it("accepts a signer once added to the local trust store", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [],
    });
    const step = witness.beginStep("interactive-session");
    witness.endStep(step, "success", {
      exitCode: 0,
    });
    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    const attestation = attestExecutionRun(getExecutionRunDir(record.run_id));
    addTrustEntry({
      keyId: attestation.keyId,
      label: "Local signer",
    });

    const verification = verifyExecutionSource(record.run_id);
    expect(verification.ok).toBe(true);
    expect(verification.attestation.state).toBe("verified");
    expect(verification.trust.state).toBe("trusted");
    expect(verification.trust.key_id).toBe(attestation.keyId);
  });

  it("reports invalid signatures separately from integrity", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [],
    });
    const step = witness.beginStep("interactive-session");
    witness.endStep(step, "success", {
      exitCode: 0,
    });
    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    const attestation = attestExecutionRun(getExecutionRunDir(record.run_id));
    const signature = JSON.parse(readFileSync(attestation.signaturePath, "utf-8"));
    signature.signature = "ZmFrZQ==";
    writeFileSync(attestation.signaturePath, JSON.stringify(signature, null, 2) + "\n");

    const verification = verifyExecutionSource(record.run_id);
    expect(verification.ok).toBe(true);
    expect(verification.integrity.ok).toBe(true);
    expect(verification.attestation.state).toBe("present-unverified");
    expect(verification.attestation.ok).toBe(false);
    expect(verification.attestation.cryptographic_valid).toBe(false);
    expect(verification.attestation.reason).toBe("invalid-signature");
  });

  it("reports missing verifier keys as present but unverified", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [],
    });
    const step = witness.beginStep("interactive-session");
    witness.endStep(step, "success", {
      exitCode: 0,
    });
    const record = witness.finalize({
      status: "success",
      finalExitCode: 0,
      cleanupAttempted: false,
      cleanupSucceeded: null,
      survivingResources: [],
    });

    const attestation = attestExecutionRun(getExecutionRunDir(record.run_id));
    const verifierKeyPath = getAttestationVerifierKeyPath(attestation.keyId);
    const hiddenKeyPath = `${verifierKeyPath}.bak`;
    renameSync(verifierKeyPath, hiddenKeyPath);

    const verification = verifyExecutionSource(record.run_id);
    expect(verification.ok).toBe(true);
    expect(verification.integrity.ok).toBe(true);
    expect(verification.attestation.state).toBe("present-unverified");
    expect(verification.attestation.ok).toBe(false);
    expect(verification.attestation.reason).toBe("verifier-key-not-found");
    expect(verification.trust.state).toBe("unknown");

    renameSync(hiddenKeyPath, verifierKeyPath);
  });
});
