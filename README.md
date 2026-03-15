# Spawn

Spawn executes operational runbooks on disposable infrastructure.

A runbook packages setup, execution, and teardown into a reproducible command that runs locally or on a cloud provider.

Spawn provisions the environment, runs the runbook, and returns the resulting session or artifacts.

ALPHA software — behavior and compatibility may change.

---

# Install

macOS / Linux (Windows via WSL2):

```
curl -fsSL https://openrouter.ai/labs/spawn/cli/install.sh | bash
```

Windows PowerShell:

```
irm https://openrouter.ai/labs/spawn/cli/install.ps1 | iex
```

---

# Usage

```
spawn
spawn <runbook> <target>
```

Examples:

```
spawn
spawn claude sprite
spawn codex hetzner
spawn codex gcp -p "add tests"
spawn delete
spawn status
```

Spawn will:

1. Provision infrastructure if needed
2. Execute the runbook
3. Inject required credentials
4. Start an interactive or headless session

---

# Core Commands

| Command                      | Description                             |
| ---------------------------- | --------------------------------------- |
| spawn                        | Interactive runbook selector            |
| spawn `<runbook>` `<target>` | Execute a runbook on a target           |
| spawn delete                 | Destroy a spawned machine               |
| spawn status                 | Show running environments               |
| spawn fix                    | Re-run setup on an existing environment |
| spawn help                   | Show CLI help                           |
| spawn version                | Show CLI version                        |

---

# Runbooks

A runbook defines:

* the environment to provision
* setup steps
* the executable workload
* cleanup behavior

Runbooks are implemented as scripts in:

```
sh/{target}/{runbook}.sh
```

Each script is responsible for preparing the environment and launching the workload.

Examples of runbooks:

* AI coding agents
* research environments
* automation tools
* infrastructure diagnostics
* operational procedures

---

# Configuration

Runbooks can be parameterized using a JSON configuration file.

Example:

```
{
  "model": "openai/gpt-5.3-codex",
  "steps": ["github"],
  "name": "dev-box"
}
```

Run with:

```
spawn codex gcp --config setup.json
```

CLI flags override config values.

---

# Non-Interactive Mode

Provide required credentials via environment variables:

```
export OPENROUTER_API_KEY=sk-or-v1-xxxxx
spawn codex hetzner
```

Cloud provider credentials vary by provider.

Example:

```
export HCLOUD_TOKEN=...
export DO_API_TOKEN=...
```

---

# How Spawn Works

Spawn orchestrates runbooks using three layers.

**CLI**

```
packages/cli/
```

Responsible for provisioning infrastructure, validating configuration, and launching runbooks.

**Runbook Scripts**

```
sh/{target}/{runbook}.sh
```

Shell scripts implementing environment setup and workload execution.

**Runbook Registry**

```
manifest.json
```

Defines supported runbooks and targets.

---

# Development

Clone the repository:

```
git clone https://github.com/VaultSovereign/spawn.git
cd spawn
```

Repository layout:

```
packages/cli/       TypeScript CLI
sh/{target}/        Runbook scripts
manifest.json       Runbook registry
```

To add a new runbook:

1. Register it in `manifest.json`
2. Implement the script under `sh/{target}/`
3. Ensure required environment variables are injected by the CLI

---

# Contributing

Contributions and bug reports are welcome.

When reporting issues include:

* the exact command used
* the runbook and target
* error output
* cloud provider used

Open an issue at:

https://github.com/VaultSovereign/spawn/issues

---

# License

Apache 2.0
