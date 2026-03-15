import pc from "picocolors";
import { exportExecutionBundle } from "../shared/proof-bundle.js";

export async function cmdBundle(runId?: string): Promise<void> {
  if (!runId) {
    console.error(pc.red("Error: bundle requires a run ID"));
    console.error(`\nUsage: ${pc.cyan("spawn bundle <run-id>")}`);
    process.exit(1);
  }

  const result = exportExecutionBundle(runId);
  console.log(`Bundled ${pc.bold(result.runId)}`);
  console.log(pc.dim(result.bundlePath));
  console.log(pc.dim(`record digest: ${result.recordDigest}`));
  console.log(pc.dim(`bundle digest: ${result.bundleDigest}`));
}
