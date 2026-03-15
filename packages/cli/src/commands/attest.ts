import pc from "picocolors";
import { attestExecutionRun } from "../shared/attestation.js";
import { getExecutionRunDir } from "../shared/execution-witness.js";

export async function cmdAttest(runId?: string): Promise<void> {
  if (!runId) {
    console.error(pc.red("Error: attest requires a run ID"));
    console.error(`\nUsage: ${pc.cyan("spawn attest <run-id>")}`);
    process.exit(1);
  }

  const result = attestExecutionRun(getExecutionRunDir(runId));
  console.log(`Attested ${pc.bold(runId)}`);
  console.log(pc.dim(result.witnessPath));
  console.log(pc.dim(result.signaturePath));
  console.log(pc.dim(`record digest: ${result.recordDigest}`));
  console.log(pc.dim(`key id: ${result.keyId}`));
}
