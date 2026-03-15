// shared/orchestrate.ts — Shared orchestration pipeline for deploying agents
// Each cloud implements CloudOrchestrator and calls runOrchestration().

import type {
  AttestationPolicy,
  RunStatus,
  StepStatus,
  TranscriptCaptureMode,
  TranscriptPolicy,
  TrustPolicy,
} from "@openrouter/spawn-shared";
import type { VMConnection } from "../history.js";
import type { CloudRunner } from "./agent-setup";
import type { AgentConfig } from "./agents";
import type { SshTunnelHandle } from "./ssh";

import { readFileSync } from "node:fs";
import { getErrorMessage } from "@openrouter/spawn-shared";
import * as v from "valibot";
import { generateSpawnId, saveLaunchCmd, saveMetadata, saveSpawnRecord } from "../history.js";
import { offerGithubAuth, wrapSshCall } from "./agent-setup";
import { tryTarballInstall } from "./agent-tarball";
import { generateEnvConfig } from "./agents";
import { createExecutionWitness } from "./execution-witness";
import { getOrPromptApiKey } from "./oauth";
import { getSpawnPreferencesPath } from "./paths";
import { asyncTryCatch, asyncTryCatchIf, isFileError, isOperationalError, tryCatchIf } from "./result.js";
import { startSshTunnel } from "./ssh";
import { ensureSshKeys, getSshKeyOpts } from "./ssh-keys";
import {
  logDebug,
  logInfo,
  logStep,
  logWarn,
  openBrowser,
  prepareStdinForHandoff,
  prompt,
  shellQuote,
  validateModelId,
  withRetry,
} from "./ui";

export interface CloudOrchestrator {
  cloudName: string;
  cloudLabel: string;
  runner: CloudRunner;
  /** When true, skip tarball + agent install (e.g. booting from a pre-baked snapshot). */
  skipAgentInstall?: boolean;
  authenticate(): Promise<void>;
  checkAccountReady?(): Promise<void>;
  promptSize(): Promise<void>;
  createServer(name: string): Promise<VMConnection>;
  getServerName(): Promise<string>;
  waitForReady(): Promise<void>;
  interactiveSession(cmd: string): Promise<number>;
  /** Return SSH connection info for tunnel support. Omit for non-SSH clouds. */
  getConnectionInfo?(): {
    host: string;
    user: string;
  };
}

/**
 * Wrap a launch command in a restart loop for cloud VMs.
 * Restarts the agent on non-zero exit (crash, SIGTERM, OOM) up to MAX_RESTARTS times.
 * Clean exits (exit code 0) break out of the loop immediately.
 * Skipped for local execution where the user controls the process directly.
 */
function wrapWithRestartLoop(cmd: string): string {
  // Shell restart loop — bash 3.x compatible (no ((var++)), no set -u)
  return [
    "_spawn_restarts=0",
    "_spawn_max=10",
    'while [ "$_spawn_restarts" -lt "$_spawn_max" ]; do',
    `  ${cmd}`,
    "  _spawn_exit=$?",
    '  if [ "$_spawn_exit" -eq 0 ]; then break; fi',
    "  _spawn_restarts=$((_spawn_restarts + 1))",
    '  printf "\\n[spawn] Agent exited with code %d. Restarting in 5s (%d/%d)...\\n" "$_spawn_exit" "$_spawn_restarts" "$_spawn_max" >&2',
    "  sleep 5",
    "done",
    'if [ "$_spawn_restarts" -ge "$_spawn_max" ]; then',
    '  printf "\\n[spawn] Agent crashed %d times. Giving up.\\n" "$_spawn_max" >&2',
    "fi",
    'exit "${_spawn_exit:-0}"',
  ].join("\n");
}

/** Options for runOrchestration (used in tests to inject mock dependencies). */
export interface OrchestrationOptions {
  tryTarball?: (runner: CloudRunner, agentName: string) => Promise<boolean>;
  getApiKey?: (agentSlug?: string, cloudSlug?: string) => Promise<string>;
}

/**
 * Load a preferred model from ~/.config/spawn/preferences.json.
 * Format: { "models": { "codex": "openai/gpt-5.3-codex", "openclaw": "anthropic/claude-sonnet-4.6" } }
 * Returns null if no preference is set or the file doesn't exist.
 */
const PreferencesSchema = v.object({
  models: v.optional(v.record(v.string(), v.string())),
});

function loadPreferredModel(agentName: string): string | null {
  const result = tryCatchIf(isFileError, () => {
    const raw = JSON.parse(readFileSync(getSpawnPreferencesPath(), "utf-8"));
    const parsed = v.safeParse(PreferencesSchema, raw);
    if (!parsed.success) {
      return null;
    }
    return parsed.output.models?.[agentName] ?? null;
  });
  return result.ok ? result.data : null;
}

function getWitnessEnvNames(cloudName: string, envPairs: string[]): string[] {
  const cloudEnvByName: Record<string, string[]> = {
    aws: [
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
      "AWS_DEFAULT_REGION",
      "LIGHTSAIL_BUNDLE",
    ],
    digitalocean: [
      "DO_API_TOKEN",
      "DO_REGION",
      "DO_DROPLET_SIZE",
    ],
    gcp: [
      "GOOGLE_APPLICATION_CREDENTIALS",
      "GCP_ZONE",
      "GCP_MACHINE_TYPE",
    ],
    hetzner: [
      "HCLOUD_TOKEN",
      "HETZNER_LOCATION",
      "HETZNER_SERVER_TYPE",
    ],
    local: [],
    sprite: [
      "SPRITE_TOKEN",
    ],
  };
  const general = [
    "OPENROUTER_API_KEY",
    "MODEL_ID",
    "SPAWN_NAME",
    "SPAWN_CONFIG_PATH",
    "SPAWN_ENABLED_STEPS",
    "GITHUB_TOKEN",
    "TELEGRAM_BOT_TOKEN",
  ];
  const agentEnvNames = envPairs.map((pair) => pair.split("=", 1)[0]).filter(Boolean);
  return Array.from(
    new Set([
      ...general,
      ...agentEnvNames,
      ...(cloudEnvByName[cloudName] ?? []),
    ]),
  );
}

function buildSurvivingResources(cloudName: string, connection?: VMConnection): Array<Record<string, string>> {
  if (!connection || cloudName === "local") {
    return [];
  }
  const resource: Record<string, string> = {
    kind: "server",
    ip: connection.ip,
    user: connection.user,
  };
  if (connection.server_id) {
    resource.server_id = connection.server_id;
  }
  if (connection.server_name) {
    resource.server_name = connection.server_name;
  }
  if (connection.cloud) {
    resource.cloud = connection.cloud;
  }
  return [
    resource,
  ];
}

function statusFromError(err: unknown): RunStatus {
  const message = getErrorMessage(err).toLowerCase();
  if (message.includes("ctrl+c") || message.includes("sigint") || message.includes("interrupted")) {
    return "aborted";
  }
  if (message.includes("timeout")) {
    return "timeout";
  }
  return "failed";
}

function parseTranscriptPolicy(value: string | undefined): TranscriptPolicy {
  if (value === "none" || value === "required") {
    return value;
  }
  return "optional";
}

function parseCaptureMode(value: string | undefined): TranscriptCaptureMode {
  if (value === "none" || value === "pty-recorded" || value === "fully-structured") {
    return value;
  }
  return "best-effort";
}

function parseAttestationPolicy(value: string | undefined): AttestationPolicy {
  if (value === "none" || value === "required") {
    return value;
  }
  return "optional";
}

function parseTrustPolicy(value: string | undefined): TrustPolicy {
  if (value === "trusted-required" || value === "allowed-set-required") {
    return value;
  }
  return "any-valid";
}

function parseWitnessArtifacts(value: string | undefined): string[] {
  if (!value) {
    return [];
  }
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export async function runOrchestration(
  cloud: CloudOrchestrator,
  agent: AgentConfig,
  agentName: string,
  options?: OrchestrationOptions,
): Promise<void> {
  if (process.env.HOME) {
    process.env.HOME = process.env.HOME.replaceAll("\\", "/");
  }
  if (process.env.SPAWN_HOME) {
    process.env.SPAWN_HOME = process.env.SPAWN_HOME.replaceAll("\\", "/");
  }
  const witness = createExecutionWitness({
    runbook: agentName,
    target: cloud.cloudName,
    envVarNames: getWitnessEnvNames(cloud.cloudName, agent.envVars("REDACTED")),
    witnessLevel: process.env.SPAWN_WITNESS_LEVEL,
    expectedArtifacts: parseWitnessArtifacts(process.env.SPAWN_WITNESS_EXPECTED_ARTIFACTS),
    requiredArtifacts: parseWitnessArtifacts(process.env.SPAWN_WITNESS_REQUIRED_ARTIFACTS),
    transcriptPolicy: parseTranscriptPolicy(process.env.SPAWN_WITNESS_TRANSCRIPT_POLICY),
    transcriptCaptureMode: parseCaptureMode(process.env.SPAWN_WITNESS_CAPTURE_MODE),
    attestationPolicy: parseAttestationPolicy(process.env.SPAWN_WITNESS_ATTESTATION_POLICY),
    trustPolicy: parseTrustPolicy(process.env.SPAWN_WITNESS_TRUST_POLICY),
    trustedSigners: parseWitnessArtifacts(process.env.SPAWN_WITNESS_TRUSTED_SIGNERS),
  });
  witness.startOutputCapture();

  const executeStep = async <T>(
    name: string,
    fn: () => Promise<T>,
    opts: {
      swallowError?: boolean;
      statusOnError?: StepStatus;
      exitCodeOnError?: number;
    } = {},
  ): Promise<T | undefined> => {
    const handle = witness.beginStep(name);
    const result = await asyncTryCatch(fn);
    if (result.ok) {
      witness.endStep(handle, "success", {
        exitCode: 0,
      });
      return result.data;
    }
    witness.endStep(handle, opts.statusOnError ?? "failed", {
      exitCode: opts.exitCodeOnError ?? 1,
      error: getErrorMessage(result.error),
    });
    if (opts.swallowError) {
      return undefined;
    }
    throw result.error;
  };

  logInfo(`${agent.name} on ${cloud.cloudLabel}`);
  process.stderr.write("\n");

  let tunnelHandle: SshTunnelHandle | undefined;
  let cleanupAttempted = false;
  let cleanupSucceeded: boolean | null = null;
  let connection: VMConnection | undefined;
  let spawnId = "";

  const orchestrationResult = await asyncTryCatch(async () => {
    await executeStep("authenticate-cloud", () => cloud.authenticate());

    if (cloud.checkAccountReady) {
      const r = await asyncTryCatch(() => executeStep("check-account-ready", () => cloud.checkAccountReady!()));
      if (!r.ok) {
        logWarn("Account readiness check failed — proceeding anyway");
        logDebug(getErrorMessage(r.error));
      }
    }

    const resolveApiKey = options?.getApiKey ?? getOrPromptApiKey;
    const apiKey = await executeStep("obtain-api-key", () => resolveApiKey(agentName, cloud.cloudName));
    if (!apiKey) {
      throw new Error("Failed to obtain API key");
    }

    if (agent.preProvision) {
      const r = await asyncTryCatch(() =>
        executeStep("pre-provision", () => agent.preProvision!(), {
          swallowError: true,
          statusOnError: "warning",
        }),
      );
      if (!r.ok) {
        logWarn("Pre-provision hook failed — continuing");
        logDebug(getErrorMessage(r.error));
      }
    }

    const rawModelId = process.env.MODEL_ID || loadPreferredModel(agentName) || agent.modelDefault;
    const modelId = rawModelId && validateModelId(rawModelId) ? rawModelId : undefined;
    if (rawModelId && !modelId) {
      logWarn(`Ignoring invalid MODEL_ID: ${rawModelId}`);
    }

    await executeStep("select-size", () => cloud.promptSize());

    spawnId = generateSpawnId();
    const serverName = await executeStep("resolve-server-name", () => cloud.getServerName());
    if (!serverName) {
      throw new Error("Failed to resolve server name");
    }
    connection = await executeStep("create-server", () => cloud.createServer(serverName));
    if (!connection) {
      throw new Error("Failed to create server");
    }

    const spawnName = process.env.SPAWN_NAME_KEBAB || process.env.SPAWN_NAME || undefined;
    saveSpawnRecord({
      id: spawnId,
      agent: agentName,
      cloud: cloud.cloudName,
      timestamp: new Date().toISOString(),
      ...(spawnName
        ? {
            name: spawnName,
          }
        : {}),
      connection,
    });
    saveMetadata(
      {
        execution_run_id: witness.runId,
      },
      spawnId,
    );
    witness.updateEnvironment({
      public_ip: connection.ip,
      connection_user: connection.user,
      ...(connection.server_id
        ? {
            server_id: connection.server_id,
          }
        : {}),
      ...(connection.server_name
        ? {
            server_name: connection.server_name,
          }
        : {}),
    });

    await executeStep("wait-for-ready", () => cloud.waitForReady());

    const envContent = generateEnvConfig(agent.envVars(apiKey));

    if (cloud.skipAgentInstall) {
      const handle = witness.beginStep("install-agent");
      logInfo("Snapshot boot — skipping agent install");
      witness.endStep(handle, "skipped", {
        exitCode: 0,
      });
    } else {
      let installedFromTarball = false;
      const betaFeatures = new Set((process.env.SPAWN_BETA ?? "").split(",").filter(Boolean));
      if (cloud.cloudName !== "local" && !agent.skipTarball && betaFeatures.has("tarball")) {
        const tarball = options?.tryTarball ?? tryTarballInstall;
        const tarballResult = await executeStep("install-agent-tarball", () => tarball(cloud.runner, agentName));
        installedFromTarball = tarballResult === true;
      }
      if (!installedFromTarball) {
        await executeStep("install-agent", () => agent.install());
      }
    }

    logStep("Setting up environment variables...");
    const envB64 = Buffer.from(envContent).toString("base64");
    const envResult = await asyncTryCatch(() =>
      executeStep("inject-environment", () =>
        withRetry(
          "env setup",
          () =>
            wrapSshCall(
              cloud.runner.runServer(
                `printf '%s' '${envB64}' | base64 -d > ~/.spawnrc && chmod 600 ~/.spawnrc; ` +
                  "for _rc in ~/.bashrc ~/.profile ~/.bash_profile ~/.zshrc; do " +
                  `grep -q 'source ~/.spawnrc' "$_rc" 2>/dev/null || echo '[ -f ~/.spawnrc ] && source ~/.spawnrc' >> "$_rc"; ` +
                  "done",
              ),
            ),
          2,
          5,
        ),
      ),
    );
    if (!envResult.ok) {
      logWarn("Environment setup had errors");
    }

    let enabledSteps: Set<string> | undefined;
    const stepsEnv = process.env.SPAWN_ENABLED_STEPS;
    if (stepsEnv !== undefined) {
      const stepNames = stepsEnv.split(",").filter(Boolean);
      if (stepNames.length > 0) {
        const { validateStepNames } = await import("./agents.js");
        const { valid, invalid } = validateStepNames(agentName, stepNames);
        if (invalid.length > 0) {
          logWarn(`Unknown setup steps ignored: ${invalid.join(", ")}`);
        }
        enabledSteps = new Set(valid);
      } else {
        enabledSteps = new Set();
      }
    }

    if (agent.configure) {
      const configResult = await asyncTryCatch(() =>
        executeStep("configure-agent", () =>
          withRetry("agent config", () => wrapSshCall(agent.configure!(apiKey, modelId, enabledSteps)), 2, 5),
        ),
      );
      if (!configResult.ok) {
        logWarn("Agent configuration failed (continuing with defaults)");
      }
    }

    if (!enabledSteps || enabledSteps.has("github")) {
      await executeStep("setup-github", () => offerGithubAuth(cloud.runner), {
        swallowError: true,
        statusOnError: "warning",
      });
    }

    if (agent.preLaunch) {
      await executeStep("pre-launch", () => agent.preLaunch());
    }

    if (agent.tunnel) {
      if (cloud.getConnectionInfo) {
        const tunnelResult = await asyncTryCatchIf(isOperationalError, () =>
          executeStep("start-tunnel", async () => {
            const conn = cloud.getConnectionInfo!();
            const keys = await ensureSshKeys();
            tunnelHandle = await startSshTunnel({
              host: conn.host,
              user: conn.user,
              remotePort: agent.tunnel!.remotePort,
              sshKeyOpts: getSshKeyOpts(keys),
            });
            if (agent.tunnel?.browserUrl) {
              const url = agent.tunnel.browserUrl(tunnelHandle.localPort);
              if (url) {
                openBrowser(url);
              }
            }
          }),
        );
        if (!tunnelResult.ok) {
          logWarn("Web dashboard tunnel failed — use the TUI instead");
        }
      } else if (cloud.cloudName === "local" && agent.tunnel.browserUrl) {
        const handle = witness.beginStep("start-tunnel");
        const url = agent.tunnel.browserUrl(agent.tunnel.remotePort);
        if (url) {
          openBrowser(url);
        }
        witness.endStep(handle, "success", {
          exitCode: 0,
        });
      }

      const tunnelMeta: Record<string, string> = {
        tunnel_remote_port: String(agent.tunnel.remotePort),
      };
      if (agent.tunnel.browserUrl) {
        const templateUrl = agent.tunnel.browserUrl(0);
        if (templateUrl) {
          tunnelMeta.tunnel_browser_url_template = templateUrl.replace("localhost:0", "localhost:__PORT__");
        }
      }
      saveMetadata(tunnelMeta, spawnId);
    }

    const ocPath = "export PATH=$HOME/.npm-global/bin:$HOME/.bun/bin:$HOME/.local/bin:$PATH";
    if (enabledSteps?.has("telegram")) {
      await executeStep("telegram-pairing", async () => {
        logStep("Telegram pairing...");
        logInfo("To pair your Telegram account:");
        logInfo("  1. Open Telegram on your phone");
        logInfo("  2. Search for the bot you created with @BotFather");
        logInfo('  3. Send it any message (e.g. "hello")');
        logInfo("  4. The bot will reply with a pairing code");
        logInfo("  5. Enter the code below");
        process.stderr.write("\n");
        const pairingCode = (await prompt("Telegram pairing code: ")).trim();
        if (pairingCode) {
          const escaped = shellQuote(pairingCode);
          const result = await asyncTryCatchIf(isOperationalError, () =>
            cloud.runner.runServer(
              `source ~/.spawnrc 2>/dev/null; ${ocPath}; openclaw pairing approve telegram ${escaped}`,
            ),
          );
          if (result.ok) {
            logInfo("Telegram paired successfully");
          } else {
            logWarn("Pairing failed — you can pair later via: openclaw pairing approve telegram <CODE>");
          }
        } else {
          logInfo("No code entered — pair later via: openclaw pairing approve telegram <CODE>");
        }
      });
    }

    if (agent.preLaunchMsg) {
      const handle = witness.beginStep("pre-launch-message");
      process.stderr.write("\n");
      logInfo(`Tip: ${agent.preLaunchMsg}`);
      witness.endStep(handle, "success", {
        exitCode: 0,
      });
    }

    logInfo(`${agent.name} is ready`);
    process.stderr.write("\n");
    logInfo(`${cloud.cloudLabel} setup completed successfully!`);
    process.stderr.write("\n");
    logStep("Starting agent...");

    prepareStdinForHandoff();

    const launchCmd = agent.launchCmd();
    saveLaunchCmd(launchCmd, spawnId);

    const sessionCmd = cloud.cloudName === "local" ? launchCmd : wrapWithRestartLoop(launchCmd);
    const sessionHandle = witness.beginStep("interactive-session");
    const exitCode = await cloud.interactiveSession(sessionCmd);
    witness.endStep(sessionHandle, exitCode === 0 ? "success" : "failed", {
      exitCode,
    });

    return exitCode;
  });

  if (!orchestrationResult.ok) {
    if (tunnelHandle) {
      cleanupAttempted = true;
      tunnelHandle.stop();
      cleanupSucceeded = true;
    }
    witness.finalize({
      status: statusFromError(orchestrationResult.error),
      finalExitCode: 1,
      cleanupAttempted,
      cleanupSucceeded,
      survivingResources: buildSurvivingResources(cloud.cloudName, connection),
    });
    witness.stopOutputCapture();
    throw orchestrationResult.error;
  }

  const exitCode = orchestrationResult.data;
  if (tunnelHandle) {
    cleanupAttempted = true;
    tunnelHandle.stop();
    cleanupSucceeded = true;
  }

  witness.finalize({
    status: exitCode === 0 ? "success" : "failed",
    finalExitCode: exitCode,
    cleanupAttempted,
    cleanupSucceeded,
    survivingResources: buildSurvivingResources(cloud.cloudName, connection),
  });
  witness.stopOutputCapture();
  process.exit(exitCode);
}
