import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { rmSync } from "node:fs";
import { attestExecutionRun } from "../shared/attestation";
import { createExecutionWitness, getExecutionRunDir } from "../shared/execution-witness";
import { verifyExecutionSource } from "../shared/proof-bundle";
import { addTrustEntry, listTrustEntries, removeTrustEntry } from "../shared/trust";

describe("trust policy", () => {
  let testSpawnHome: string;
  let savedSpawnHome: string | undefined;

  beforeEach(() => {
    savedSpawnHome = process.env.SPAWN_HOME;
    const home = (process.env.HOME ?? process.env.USERPROFILE ?? "").replaceAll("\\", "/");
    testSpawnHome = `${home}/.spawn-test-trust-${Date.now()}-${Math.random().toString(16).slice(2)}`;
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

  it("keeps trust separate from valid attestation for unknown signers", () => {
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

    attestExecutionRun(getExecutionRunDir(record.run_id));
    const verification = verifyExecutionSource(record.run_id);

    expect(verification.attestation.state).toBe("verified");
    expect(verification.trust.state).toBe("unknown");
    expect(verification.policy.ok).toBe(true);
  });

  it("fails policy when a trusted signer is required but not accepted", () => {
    const witness = createExecutionWitness({
      runbook: "codex",
      target: "local",
      envVarNames: [],
      attestationPolicy: "required",
      trustPolicy: "trusted-required",
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
    const verification = verifyExecutionSource(record.run_id);

    expect(verification.attestation.state).toBe("verified");
    expect(verification.trust.state).toBe("unknown");
    expect(verification.policy.ok).toBe(false);
    expect(verification.ok).toBe(false);
    expect(verification.errors).toContain("Trusted signer required by policy but not accepted");

    addTrustEntry({
      keyId: attestation.keyId,
      label: "Primary signer",
    });
    const accepted = verifyExecutionSource(record.run_id);
    expect(accepted.trust.state).toBe("trusted");
    expect(accepted.policy.ok).toBe(true);
    expect(accepted.ok).toBe(true);
  });

  it("reports revoked signers separately from attestation validity", () => {
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
      label: "Revoked signer",
      state: "revoked",
    });

    const verification = verifyExecutionSource(record.run_id);
    expect(verification.attestation.state).toBe("verified");
    expect(verification.trust.state).toBe("revoked");
    expect(verification.ok).toBe(true);
  });

  it("supports local trust store add and remove operations", () => {
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
      label: "Listed signer",
    });

    expect(listTrustEntries().some((entry) => entry.key_id === attestation.keyId)).toBe(true);
    expect(removeTrustEntry(attestation.keyId)).toBe(true);
    expect(listTrustEntries().some((entry) => entry.key_id === attestation.keyId)).toBe(false);
  });
});
