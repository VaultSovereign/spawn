import pc from "picocolors";
import { tryCatch } from "../shared/result.js";
import {
  addTrustEntry,
  describeTrustStoreError,
  formatTrustList,
  listTrustEntries,
  removeTrustEntry,
} from "../shared/trust.js";

function usage(): never {
  console.error(`Usage: ${pc.cyan("spawn trust <add|remove|list> [args]")}`);
  process.exit(1);
}

function extractOption(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index === -1) {
    return undefined;
  }
  const value = args[index + 1];
  if (!value || value.startsWith("-")) {
    console.error(pc.red(`Error: ${flag} requires a value`));
    usage();
  }
  args.splice(index, 2);
  return value;
}

export async function cmdTrust(args: string[]): Promise<void> {
  const [subcommand, ...rest] = args;
  if (!subcommand || subcommand === "help" || subcommand === "--help" || subcommand === "-h") {
    usage();
  }

  if (subcommand === "list") {
    const lines = formatTrustList(listTrustEntries());
    for (const line of lines) {
      console.log(line);
    }
    return;
  }

  if (subcommand === "remove") {
    const keyId = rest[0];
    if (!keyId) {
      console.error(pc.red("Error: trust remove requires a key ID"));
      usage();
    }
    if (!removeTrustEntry(keyId)) {
      console.error(pc.red(`Signer not found in trust store: ${keyId}`));
      process.exit(1);
    }
    console.log(`Removed trusted signer ${pc.bold(keyId)}`);
    return;
  }

  if (subcommand === "add") {
    const mutableArgs = [
      ...rest,
    ];
    const label = extractOption(mutableArgs, "--label");
    const scope = extractOption(mutableArgs, "--scope");
    const keyId = mutableArgs[0];
    if (!keyId) {
      console.error(pc.red("Error: trust add requires a key ID"));
      usage();
    }
    const addResult = tryCatch(() =>
      addTrustEntry({
        keyId,
        label: label ?? (mutableArgs.slice(1).join(" ") || undefined),
        scope,
      }),
    );
    if (!addResult.ok) {
      console.error(pc.red(`Error: ${describeTrustStoreError(addResult.error)}`));
      process.exit(1);
    }
    const entry = addResult.data;
    console.log(`Trusted signer ${pc.bold(entry.key_id)}`);
    console.log(pc.dim(`label=${entry.label} scope=${entry.scope} state=${entry.state}`));
    return;
  }

  console.error(pc.red(`Unknown trust subcommand: ${subcommand}`));
  usage();
}
