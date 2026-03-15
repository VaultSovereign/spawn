import { useMemo, useState } from "react";

interface ManifestAgent {
  name?: string;
  description?: string;
  tagline?: string;
  category?: string;
  runtime?: string;
  featured_cloud?: string[];
  tags?: string[];
}

interface SpawnManifest {
  agents?: Record<string, ManifestAgent>;
}

interface CommandOption {
  id: string;
  label: string;
  intent: string;
  preview: (runbookId: string, target: string) => string;
}

interface RunbookOption {
  id: string;
  title: string;
  subtitle: string;
  runtime: string;
  category: string;
  target: string;
}

const commandOptions: CommandOption[] = [
  {
    id: "run",
    label: "Run",
    intent: "Launch a witnessed execution",
    preview: (runbookId, target) => `spawn ${runbookId} ${target} --emit-proof`,
  },
  {
    id: "verify",
    label: "Verify",
    intent: "Check integrity, capture, and policy",
    preview: () => "spawn verify spn_9f4c2b",
  },
  {
    id: "bundle",
    label: "Bundle",
    intent: "Export a portable proof archive",
    preview: () => "spawn bundle spn_9f4c2b",
  },
  {
    id: "attest",
    label: "Attest",
    intent: "Attach a detached signature",
    preview: () => "spawn attest spn_9f4c2b",
  },
  {
    id: "status",
    label: "Status",
    intent: "Inspect live cloud resources",
    preview: (_, target) => `spawn status -c ${target}`,
  },
  {
    id: "fix",
    label: "Fix",
    intent: "Re-run setup on an existing VM",
    preview: () => "spawn fix spn_9f4c2b",
  },
];

function buildRunbooks(input: SpawnManifest): RunbookOption[] {
  const entries = Object.entries(input.agents ?? {});
  return entries
    .map(([id, agent]) => ({
      id,
      title: agent.name ?? id,
      subtitle: agent.tagline ?? agent.description ?? "Witnessed execution profile",
      runtime: agent.runtime ?? "unknown",
      category: agent.category ?? "agent",
      target: agent.featured_cloud?.[0] ?? "local",
    }))
    .sort((a, b) => a.title.localeCompare(b.title));
}

export default function OpenRouterMobileMirror({ manifest }: { manifest: SpawnManifest }) {
  const runbooks = useMemo(() => buildRunbooks(manifest), [manifest]);
  const [selectedRunbookId, setSelectedRunbookId] = useState(runbooks[0]?.id ?? "codex");
  const [selectedCommands, setSelectedCommands] = useState<string[]>(["run", "verify", "bundle"]);

  const activeRunbook =
    runbooks.find((item) => item.id === selectedRunbookId) ??
    runbooks[0] ?? {
      id: "codex",
      title: "Codex CLI",
      subtitle: "OpenAI's open-source coding agent",
      runtime: "node",
      category: "cli",
      target: "local",
    };

  const selectedCommandObjects = commandOptions.filter((command) => selectedCommands.includes(command.id));

  function toggleCommand(id: string) {
    setSelectedCommands((current) => {
      if (current.includes(id)) {
        return current.length === 1 ? current : current.filter((item) => item !== id);
      }
      return [...current, id];
    });
  }

  const commandPreview = selectedCommandObjects.map((command) =>
    command.preview(activeRunbook.id, activeRunbook.target),
  );

  return (
    <div className="mirror-shell">
      <div className="phone-frame">
        <div className="status-bar">
          <span>1:46</span>
          <div className="status-icons">
            <div className="signal-bars" aria-hidden="true">
              <span />
              <span />
              <span />
              <span />
            </div>
            <div className="wifi-ring" aria-hidden="true" />
            <div className="battery-pill" aria-hidden="true">
              <div className="battery-fill" />
            </div>
          </div>
        </div>

        <div className="browser-row">
          <button className="circle-button" type="button" aria-label="Home">
            ⌂
          </button>
          <div className="address-pill">
            <span className="address-icon">⌘</span>
            <span className="address-text">spawn://mirror/runbooks-and-commands</span>
          </div>
          <button className="ghost-button" type="button">
            +
          </button>
          <div className="tab-count">4</div>
          <button className="ghost-button" type="button">
            ⋮
          </button>
        </div>

        <div className="brand-row">
          <div>
            <div className="eyebrow">Portable proof UI</div>
            <h1>Spawn Mirror</h1>
          </div>
          <div className="brand-actions">
            <div className="compact-pill">Runbooks</div>
            <div className="avatar-core" />
          </div>
        </div>

        <div className="panel title-panel">
          <div>
            <div className="title-label">Selected runbook</div>
            <div className="title-value">{activeRunbook.title}</div>
          </div>
          <div className="title-meta">{activeRunbook.target}</div>
        </div>

        <div className="chip-row">
          <div className="chip chip-active">{activeRunbook.title}</div>
          {selectedCommandObjects.slice(0, 2).map((command) => (
            <div className="chip" key={command.id}>
              {command.label}
            </div>
          ))}
        </div>

        <div className="content-grid">
          <section className="panel section-panel">
            <div className="section-heading">
              <div>
                <div className="section-label">Runbooks</div>
                <h2>Choose an execution profile</h2>
              </div>
              <span>{runbooks.length}</span>
            </div>
            <div className="runbook-list">
              {runbooks.slice(0, 6).map((runbook) => {
                const active = runbook.id === activeRunbook.id;
                return (
                  <button
                    className={`selector-card${active ? " selector-card-active" : ""}`}
                    key={runbook.id}
                    onClick={() => setSelectedRunbookId(runbook.id)}
                    type="button"
                  >
                    <div className="selector-topline">
                      <span>{runbook.title}</span>
                      <span>{runbook.target}</span>
                    </div>
                    <div className="selector-subline">{runbook.subtitle}</div>
                    <div className="selector-meta">
                      <span>{runbook.category}</span>
                      <span>{runbook.runtime}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </section>

          <section className="panel section-panel">
            <div className="section-heading">
              <div>
                <div className="section-label">Commands</div>
                <h2>Build the operator stack</h2>
              </div>
              <span>{selectedCommands.length} active</span>
            </div>
            <div className="command-list">
              {commandOptions.map((command) => {
                const active = selectedCommands.includes(command.id);
                return (
                  <button
                    className={`command-card${active ? " command-card-active" : ""}`}
                    key={command.id}
                    onClick={() => toggleCommand(command.id)}
                    type="button"
                  >
                    <div className="command-title">{command.label}</div>
                    <div className="command-intent">{command.intent}</div>
                  </button>
                );
              })}
            </div>
          </section>
        </div>

        <div className="suggestions-row">
          {selectedCommandObjects.map((command) => (
            <div className="suggestion-card" key={command.id}>
              <div className="suggestion-title">{command.label}</div>
              <div className="suggestion-subtitle">{command.intent}</div>
            </div>
          ))}
        </div>

        <div className="composer-shell">
          <div className="composer-topline">
            <div className="composer-tag">Execution plan</div>
            <div className="composer-tag composer-tag-accent">Witnessed</div>
          </div>

          <div className="composer-text">
            {`Run ${activeRunbook.title} on ${activeRunbook.target} with ${selectedCommands.length} selected command${
              selectedCommands.length === 1 ? "" : "s"
            }.`}
          </div>

          <div className="command-preview-list">
            {commandPreview.map((preview) => (
              <div className="command-preview" key={preview}>
                {preview}
              </div>
            ))}
          </div>

          <div className="composer-footer">
            <div className="footer-icons">
              <span>⌘</span>
              <span>◌</span>
              <span>PTY</span>
            </div>
            <button className="launch-button" type="button">
              ↑
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
