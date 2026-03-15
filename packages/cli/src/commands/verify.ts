import pc from "picocolors";
import { verifyExecutionSource } from "../shared/proof-bundle.js";

export async function cmdVerify(runId?: string): Promise<void> {
  if (!runId) {
    console.error(pc.red("Error: verify requires a run ID"));
    console.error(`\nUsage: ${pc.cyan("spawn verify <run-id|bundle-path>")}`);
    process.exit(1);
  }

  const result = verifyExecutionSource(runId);
  if (!result.ok) {
    console.error(pc.red(`Proof verification failed for ${pc.bold(runId)}`));
    console.error(pc.dim(result.runDir));
    console.error(
      pc.dim(
        `integrity=${result.integrity.ok ? "ok" : "failed"} capture=${result.capture.interactive_transcript} policy=${result.policy.ok ? "ok" : "failed"} attestation=${result.attestation.state} trust=${result.trust.state}`,
      ),
    );
    for (const error of result.errors) {
      console.error(`  - ${error}`);
    }
    process.exit(1);
  }

  console.log(`Verified ${pc.bold(runId)}`);
  console.log(pc.dim(result.runDir));
  if (result.digest) {
    console.log(pc.dim(`digest: ${result.digest}`));
  }
  if (result.transport.bundle_digest) {
    console.log(pc.dim(`bundle digest: ${result.transport.bundle_digest}`));
  }
  console.log(
    pc.dim(
      `integrity=ok capture=${result.capture.interactive_transcript} (${result.capture.mode}) policy=${result.policy.transcript_policy}/${result.policy.attestation_policy}/${result.policy.trust_policy} attestation=${result.attestation.state} trust=${result.trust.state}`,
    ),
  );
  if (result.attestation.state !== "none") {
    const suffix = result.attestation.reason ? ` (${result.attestation.reason})` : "";
    console.log(
      pc.dim(
        `attestation subject=${result.attestation.subject} key=${result.attestation.key_id ?? "unknown"}${suffix}`,
      ),
    );
  }
  if (result.trust.state !== "none") {
    const suffix = result.trust.reason ? ` (${result.trust.reason})` : "";
    console.log(pc.dim(`trust key=${result.trust.key_id ?? "unknown"} state=${result.trust.state}${suffix}`));
  }
}
