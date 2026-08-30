# Hardening non-Claude agent harnesses against secret/environment disclosure

Research date: **2026-08-30**. Every claim below is tied to a primary source URL (official docs
or the project's own GitHub repo). Where I could not verify something from a primary source it is
marked **[UNVERIFIED]**.

Versions checked:

- **OpenCode** — latest release `v1.18.25`, published 2026-08-28. Canonical repo is now
  `anomalyco/opencode`; `sst/opencode` redirects to it (verified via `gh api repos/sst/opencode`,
  which returns `full_name: anomalyco/opencode`).
- **Gemini CLI** — `main` at 2026-08-30, nightly `v0.59.0-nightly.20260830` (via
  `gh api repos/google-gemini/gemini-cli/releases`).
- **Cursor** — changelog latest entry 2026-08-27 (<https://cursor.com/changelog>). Docs reference
  behaviour "starting in Cursor 3.11".
- **GitHub Copilot** — docs.github.com as of 2026-08-30.

---

## Cross-cutting reality check (read this first)

Three failure modes recur in *every* harness below. A scanner should treat them as the default
assumption unless proven otherwise:

1. **Ignore files usually gate the *file-read tool*, not the *shell tool*.** An agent that can run
   `bash` can `cat .env` regardless of `.cursorignore` / `.clineignore` / `.geminiignore`. Cursor
   says this explicitly: "The terminal and MCP server tools used by Agent cannot block access to
   code governed by `.cursorignore`"
   (<https://cursor.com/docs/context/ignore-files>). Roo Code is the notable partial exception (it
   pattern-matches a *predefined list* of read commands — see §D).
2. **Vendors disclaim these controls as security boundaries.** Cursor: allowlists and autoRun
   instructions are "best-effort convenience" and Run Modes are "best-effort guardrails rather than
   a hard security boundary" (<https://cursor.com/docs/agent/security>,
   <https://cursor.com/docs/reference/permissions>). Roo: ".rooignore is a powerful tool for
   controlling Roo's file access via its tools, but it does not create a system-level sandbox"
   (<https://roocodeinc.github.io/Roo-Code/features/rooignore>).
3. **The hardening that actually holds is at a different layer**: OS/container sandbox
   (Gemini CLI seatbelt/docker, Cursor sandbox.json, Copilot CLI MXC), network egress
   allowlists, and deny-precedence permission rules. Ignore files are a defence-in-depth
   nicety on top.

---

## A. OpenCode

### A.1 Config file locations and precedence

Merged (not replaced), lowest → highest precedence
(<https://opencode.ai/docs/config/>):

1. Remote config (`.well-known/opencode`)
2. Global: `~/.config/opencode/opencode.json`
3. `OPENCODE_CONFIG` env var (custom path)
4. **Project: `opencode.json` in project root** ← committable
5. `.opencode` directories
6. `OPENCODE_CONFIG_CONTENT` env var (inline)
7. Managed config files (system directories)
8. macOS managed preferences (MDM)

JSON and JSONC (comments) are both accepted; schema is `https://opencode.ai/config.json`
(<https://opencode.ai/docs/config/>). The published schema confirms the top-level Config keys:
`agent, attachment, autoshare, autoupdate, command, compaction, default_agent, disabled_providers,
enabled_providers, enterprise, experimental, formatter, instructions, layout, logLevel, lsp, mcp,
mode, model, permission, plugin, provider, reference, references, server, share, shell, skills,
small_model, snapshot, subagent_depth, tool_output, tools, username, watcher` (fetched from
<https://opencode.ai/config.json>, `$defs.Config.properties`).

**Committable to the repo:** `opencode.json` / `opencode.jsonc` at project root, plus
`.opencode/` (agents, plans). Global-only: `~/.config/opencode/opencode.json` and
`~/.config/opencode/AGENTS.md` (<https://opencode.ai/docs/rules/>).

Important: because configs **merge**, a project `opencode.json` cannot *remove* a permissive
global rule — it can only add a rule that wins by being later/more specific. And a malicious
repo's `opencode.json` is itself part of the merge, so a scanner should flag repo configs that
*loosen* permissions.

### A.2 Permission keys and syntax

Full key list (<https://opencode.ai/docs/permissions/>): `read`, `edit` (covers edit/write/patch),
`glob`, `grep`, `bash`, `task`, `skill`, `lsp`, `question`, `webfetch`, `websearch`,
`external_directory`, `doom_loop`. The schema confirms these plus `list` and `todowrite`
(<https://opencode.ai/config.json>, `$defs.PermissionConfig`). Values are exactly
`"ask" | "allow" | "deny"` (`$defs.PermissionActionConfig`).

Pattern rules use `*` / `?` wildcards and **the last matching rule wins**
(<https://opencode.ai/docs/permissions/>) — note this is the *opposite* of Cursor/Copilot's
"deny always wins".

Hardened starting point (project-committable `opencode.json`):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "share": "disabled",
  "permission": {
    "*": "ask",
    "read": {
      "*": "allow",
      "**/.env": "deny",
      "**/.env.*": "deny",
      "**/*.env": "deny",
      "**/*.pem": "deny",
      "**/*.key": "deny",
      "**/id_rsa*": "deny",
      "**/id_ed25519*": "deny",
      "**/.npmrc": "deny",
      "**/.netrc": "deny",
      "~/.ssh/**": "deny",
      "~/.aws/**": "deny",
      "~/.config/gcloud/**": "deny",
      "~/.kube/**": "deny",
      "**/.env.example": "allow"
    },
    "edit": { "*": "ask" },
    "bash": {
      "*": "ask",
      "git status": "allow",
      "git diff *": "allow",
      "npm test *": "allow",
      "env": "deny",
      "printenv*": "deny",
      "curl *": "deny",
      "wget *": "deny",
      "cat *.env*": "deny",
      "cat ~/.ssh/*": "deny",
      "cat ~/.aws/*": "deny"
    },
    "webfetch": "ask",
    "websearch": "ask",
    "external_directory": { "*": "deny" }
  }
}
```

`~` and `$HOME` expand in patterns (<https://opencode.ai/docs/permissions/>). `external_directory`
is the dedicated key for "tool access outside project"; `"*": "deny"` is the out-of-repo lock.

**Caveat on the `bash` denylist above:** it is pattern matching over parsed commands, and is
trivially bypassed (`c""at .env`, `python -c "print(open('.env').read())"`, base64, a shell
script). Treat `"bash": {"*": "ask"}` or `"bash": "deny"` as the only reliable posture; treat
command-level denies as speed bumps, not boundaries.

### A.3 Verified defaults (source, not docs)

The docs claim ".env files denied by default". **The source says `ask`, not `deny`.** From
`packages/opencode/src/agent/agent.ts` on `main`
(<https://github.com/anomalyco/opencode/blob/main/packages/opencode/src/agent/agent.ts>):

```ts
const defaults = Permission.fromConfig({
  "*": "allow",
  doom_loop: "ask",
  external_directory: { "*": "ask", /* + whitelisted tmp/skill/reference dirs */ },
  question: "deny",
  plan_enter: "deny",
  plan_exit: "deny",
  // mirrors github.com/github/gitignore Node.gitignore pattern for .env files
  read: { "*": "allow", "*.env": "ask", "*.env.*": "ask", "*.env.example": "allow" },
})
```

So out of the box: **everything is `allow`**, `.env` reads only *prompt*, external directories
only *prompt*, and — critically — **the `.env` guard is on the `read` tool only**. `bash` is
`allow` by default, so `cat .env` is unprompted on a default install. Built-in agents `plan`,
`general`, `explore` layer extra restrictions on top of these defaults (same file).

### A.4 Agent-level permissions

Agent rules take precedence over global (<https://opencode.ai/docs/permissions/>):

```json
{
  "agent": {
    "build": {
      "permission": { "bash": { "git commit *": "deny", "git push *": "deny" } }
    }
  }
}
```

Agents also live as Markdown-with-frontmatter files: project `.opencode/agents/*.md`, global
`~/.config/opencode/agents/*.md`; filename = agent id; frontmatter supports `mode`
(`primary` / `subagent` / `all`), `permission`, `model`, `tools`
(<https://opencode.ai/docs/agents/>). **Repo-committed agent files can widen permissions** —
a scanner must read `.opencode/agents/*.md`, not just `opencode.json`.

### A.5 Disabling tools outright

```json
{ "tools": { "write": false, "bash": false } }
```

(<https://opencode.ai/docs/config/>). Schema type is `{ [toolName: string]: boolean }`
(<https://opencode.ai/config.json>). Built-in tool names: `bash, edit, write, read, grep, glob,
lsp, apply_patch, skill, todowrite, webfetch, websearch, question`
(<https://opencode.ai/docs/tools/>).

### A.6 Ignore files

**There is no first-party `.opencodeignore`.** The docs contain no ignore-file mechanism
(<https://opencode.ai/docs/rules/>). What exists:

- `grep` and `glob` use ripgrep, which **respects `.gitignore` by default**
  (<https://opencode.ai/docs/tools/>). This is *search filtering*, not access control —
  `read` and `bash` are unaffected.
- `watcher.ignore` excludes dirs from file **monitoring** only (<https://opencode.ai/docs/config/>).
- A third-party plugin `opencode-ignore` implements gitignore-style access blocking
  (<https://github.com/lgladysz/opencode-ignore>). Community, not vendor — treat accordingly.

So the only vendor-supported way to block secret reads in OpenCode is the `permission.read`
deny map (§A.2).

### A.7 MCP restrictions

```json
{ "mcp": { "jira": { "type": "remote", "url": "https://...", "enabled": false } } }
```

Local servers use `"type": "local"`, `"command": [...]`, `"environment": { ... }`; remote use
`"url"` and `"headers"` (<https://opencode.ai/docs/mcp-servers/>). There is **no documented
per-MCP-tool permission gating** — the docs do not describe permission gating for MCP tools
(<https://opencode.ai/docs/mcp-servers/>). MCP tool names land in the generic
`permission` object via `additionalProperties` in the schema, so a `"*": "ask"` default should
catch them, but I could not find docs confirming the naming convention. **[UNVERIFIED: exact
permission key format for MCP tools.]**

Note the exfil surface: `mcp.<name>.environment` and `mcp.<name>.headers` accept
`"{env:VAR_NAME}"` and `"{file:path}"` substitution (<https://opencode.ai/docs/config/>), so a
repo-committed `opencode.json` can pipe local env vars / file contents to an attacker-controlled
remote MCP URL. **This is the single highest-risk pattern to scan for in an OpenCode repo.**

### A.8 Env-var exposure

- Config strings support `{env:VARIABLE_NAME}` and `{file:path/to/file}` substitution
  (<https://opencode.ai/docs/config/>).
- No documented env-var redaction feature (contrast Gemini CLI's
  `security.environmentVariableRedaction`).
- `bash` defaults to `allow`, so `env` / `printenv` dumps the whole environment on a default install.

### A.9 Training / privacy / data routing

- **OpenCode itself:** "OpenCode does not store your code or context data. All processing happens
  locally or through direct API calls to your AI provider." Exception: `/share`
  (<https://opencode.ai/docs/enterprise/>).
- **Sharing:** `share` accepts `"manual"` (default), `"auto"`, `"disabled"`. Sharing "syncs your
  conversation history to our servers" and publishes at `opncd.ai/s/<share-id>`. Disable with
  `{"share": "disabled"}`, and the docs explicitly recommend committing that to the repo for team
  enforcement (<https://opencode.ai/docs/share/>). There is also a separate top-level `autoshare`
  key in the schema (<https://opencode.ai/config.json>).
- **Zen** is an optional AI gateway, **not** on by default — "you don't need to use it to use
  OpenCode" and you must sign up and connect a key (<https://opencode.ai/docs/zen/>). Zen providers
  are zero-retention with named exceptions: OpenAI and Anthropic APIs retain requests 30 days;
  several free/trial models (e.g. Big Pickle, an NVIDIA Nemotron free endpoint, a "Muse Spark
  Contributor Free" tier that trades discounted tokens for training rights) do collect/train
  (<https://opencode.ai/docs/zen/>, <https://opencode.ai/legal/privacy-policy>).
- **Telemetry:** `experimental.openTelemetry` (boolean) — "Enable OpenTelemetry spans for AI SDK
  calls" (from <https://opencode.ai/config.json>). There is no documented product-analytics opt-out
  key beyond this. Community reports allege outbound connections persist after disabling telemetry
  and that session titles may be computed remotely
  (<https://github.com/anomalyco/opencode/issues/10416>,
  <https://github.com/anomalyco/opencode/issues/5554>). **[UNVERIFIED — issue reports, not vendor
  confirmation. Egress-test before trusting.]**
- **Provider lockdown:** `disabled_providers` / `enabled_providers` exist in the schema
  (<https://opencode.ai/config.json>); enterprise guidance is to route everything through an
  internal gateway and "disable other AI providers"
  (<https://opencode.ai/docs/enterprise/>).

### A.10 Known gaps (OpenCode)

| Gap | Evidence |
|---|---|
| Default posture is `"*": "allow"` — a fresh install auto-runs bash, edits, webfetch | source `agent.ts` |
| `.env` protection is `ask` (not deny) and applies **only to the `read` tool** | source `agent.ts` |
| No first-party ignore file; `.gitignore` only filters grep/glob via ripgrep | <https://opencode.ai/docs/tools/> |
| "Last matching rule wins" means a later broad `allow` silently overrides an earlier `deny` | <https://opencode.ai/docs/permissions/> |
| Merged config: a repo `opencode.json` participates in the merge and can loosen posture | <https://opencode.ai/docs/config/> |
| `{env:...}` / `{file:...}` in MCP headers/env is a direct exfiltration primitive | <https://opencode.ai/docs/config/> |
| `--auto` flag auto-approves anything not explicitly denied | <https://opencode.ai/docs/permissions/> |
| `share: "auto"` publishes every session to a public URL | <https://opencode.ai/docs/share/> |

### A.11 Detection checklist — OpenCode

Scan for, in `opencode.json` / `opencode.jsonc` / `.opencode/**`:

- [ ] `permission` block present at all. If absent → default `"*": "allow"` posture. **Fail.**
- [ ] `permission["*"]` is `"ask"` or `"deny"` (not `"allow"`), or `permission` is the string `"ask"`.
- [ ] `permission.bash` is `"ask"`/`"deny"` or an object whose `"*"` is `"ask"`/`"deny"`.
- [ ] `permission.read` contains `deny` (not just `ask`) entries for `.env*`, `*.pem`, `*.key`,
      `id_rsa*`, `.netrc`, `.npmrc`, `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`, `~/.kube/**`.
- [ ] `permission.external_directory` set to `"deny"` (default is only `"ask"`).
- [ ] `permission.webfetch` / `websearch` are `"ask"`/`"deny"`.
- [ ] **Anti-pattern:** any rule ordered *after* a deny that re-allows the same path (last-wins).
- [ ] **Anti-pattern:** `"permission": "allow"` (string form) anywhere.
- [ ] **Anti-pattern:** `mcp.*.headers` or `mcp.*.environment` containing `{env:` or `{file:`
      alongside a non-localhost `url` → exfiltration primitive.
- [ ] `mcp.*.enabled: false` for anything not explicitly needed; no unpinned `npx -y` MCP commands.
- [ ] `share` is `"disabled"`; `autoshare` is absent/false.
- [ ] `tools` map disables `bash`/`write`/`webfetch` where the repo doesn't need them.
- [ ] `.opencode/agents/*.md` frontmatter — check each agent's `permission` block doesn't widen
      the global one (agent rules take precedence).
- [ ] `disabled_providers` / `enabled_providers` pin the provider set.
- [ ] CI/scripts do not invoke `opencode --auto` or `opencode run --auto`.
- [ ] `.gitignore` covers `.env*`, `*.pem`, `*.key` (helps grep/glob only, but cheap).

---

## B. Gemini CLI

Gemini CLI has, as of 2026-08, the **most complete permission model of the four** — a TOML policy
engine with deny-by-exclusion, plus a real process sandbox, plus env-var redaction. It is also the
most complicated to audit.

### B.1 Config file locations and precedence

Lowest → highest (<https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md>):

1. Hardcoded defaults
2. **System defaults file** — `/etc/gemini-cli/system-defaults.json` (Linux),
   `C:\ProgramData\gemini-cli\system-defaults.json` (Windows),
   `/Library/Application Support/GeminiCli/system-defaults.json` (macOS)
3. **User** — `~/.gemini/settings.json`
4. **Project** — `.gemini/settings.json` ← committable
5. **System overrides** — `/etc/gemini-cli/settings.json` / `C:\ProgramData\gemini-cli\settings.json`
   / `/Library/Application Support/GeminiCli/settings.json` (wins over everything else)
6. Environment variables (incl. from `.env` files)
7. CLI arguments

Note the ordering trap: **project settings override user settings.** A repo can loosen a
developer's personal hardening. Only the *system* settings file and admin policies/console
controls are above the project layer.

Also in `.gemini/`: custom sandbox profiles `.gemini/sandbox-macos-custom.sb` and
`.gemini/sandbox.Dockerfile` (same doc) — both repo-committable and both **executable
configuration**, so both are scan targets.

Schema for editor validation:
`https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json`.

### B.2 Policy engine (the real control)

Docs: <https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md>

TOML rules, `.toml` files, tiers with base priorities:

| Tier | Base | Location |
|---|---|---|
| Default | 1 | ships with CLI |
| Extension | 2 | from extensions |
| **Workspace** | 3 | `$WORKSPACE_ROOT/.gemini/policies/*.toml` — **currently non-functional** |
| User | 4 | `~/.gemini/policies/*.toml` |
| Admin | 5 | `/etc/gemini-cli/policies` (Linux), `/Library/Application Support/GeminiCli/policies` (macOS), `C:\ProgramData\gemini-cli\policies` (Windows) |

> ⚠️ **Critical for "committable to the repo":** the docs carry an explicit warning — "The
> **Workspace** tier (project-level policies) is currently non-functional. Defining policies in a
> workspace's `.gemini/policies` directory will not have any effect. See
> [issue #18186](https://github.com/google-gemini/gemini-cli/issues/18186). Use User or Admin
> policies instead."
> **So you cannot ship Gemini CLI policy hardening in a repo today.** A repo containing
> `.gemini/policies/*.toml` is expressing intent, not enforcing anything.

Final priority = `tier_base + (toml_priority / 1000)`, toml priority 0–999, highest wins.

Rule schema (verbatim fields from the doc): `toolName` (string or array; wildcards `*`,
`mcp_server_*`, `mcp_*_toolName`, `mcp_*`), `subagent`, `mcpName`, `toolAnnotations`,
`argsPattern` (regex over stable-JSON args), `commandPrefix`, `commandRegex`, `decision`
(`allow`|`deny`|`ask_user`), `priority`, `denyMessage`, `modes`, `interactive`, `allowRedirection`.

`deny` is the strong primitive: "For global rules (those without an `argsPattern`), tools that are
denied are **completely excluded from the model's memory**." The docs also state the legacy
`tools.exclude` setting is **deprecated in favour of policy rules with a `deny` decision**.

Hardened `~/.gemini/policies/secrets.toml`:

```toml
# Block reading secret material outright.
[[rule]]
toolName = ["read_file", "read_many_files"]
argsPattern = '(\.env|\.pem|\.key|id_rsa|id_ed25519|\.netrc|\.npmrc|/\.ssh/|/\.aws/|/\.kube/|/\.config/gcloud/)'
decision = "deny"
priority = 900
denyMessage = "Reading credential material is blocked by policy."

# Block shell commands that dump env or read credential paths.
[[rule]]
toolName = "run_shell_command"
commandRegex = '(env\b|printenv|\.env|/\.ssh/|/\.aws/|aws configure|gcloud auth|kubectl config view)'
decision = "deny"
priority = 900
denyMessage = "Credential/environment disclosure is blocked by policy."

# Everything else in the shell asks.
[[rule]]
toolName = "run_shell_command"
decision = "ask_user"
priority = 100

# All writes ask.
[[rule]]
toolName = ["write_file", "replace"]
decision = "ask_user"
priority = 100

# Network tools ask.
[[rule]]
toolName = ["web_fetch", "google_web_search"]
decision = "ask_user"
priority = 100

# Every MCP tool from every server asks.
[[rule]]
toolName = "*"
mcpName = "*"
decision = "ask_user"
priority = 50
```

Gotchas the docs call out:

- `commandRegex` is tested against the JSON representation `{"command":"..."}`, so `^` and `$`
  anchor the JSON string, not the command — "Anchors like `^` or `$` apply to the full JSON string,
  so `^` should usually be avoided here."
- Redirection (`>`, `>>`, `<`, `<<`, `<<<`) triggers confirmation by default even on matched rules
  unless `allowRedirection = true` — a useful anti-exfil default.
- "**Do not use underscores (`_`) in your MCP server names**… the parser will misinterpret the
  server identity, which can cause wildcard rules and security policies to **fail silently**."
  This is a live footgun: `mcp_my_server_tool` breaks `mcp_*` rules.
- Admin policies in the standard system dir are ignored unless the dir is root-owned and
  not group/world-writable (Linux/macOS) or in `C:\ProgramData` without standard-user write
  (Windows). Supplemental admin policies via `--admin-policy` / `adminPolicyPaths` are **not**
  subject to those checks — and are ignored entirely if standard-location policies exist.

Approval modes: `default`, `autoEdit`, `plan` (strict read-only), `yolo`. Persisted "Allow for all
future sessions" approvals cascade to *more permissive* modes only (`plan` < `default` <
`autoEdit` < `yolo`).

### B.3 settings.json security keys

All from
<https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md>
(defaults quoted from the doc):

**File filtering**
- `context.fileFiltering.respectGitIgnore` (default `true`) — "Respect .gitignore files when searching."
- `context.fileFiltering.respectGeminiIgnore` (default `true`) — "Respect .geminiignore files when searching."
- `context.fileFiltering.customIgnoreFilePaths` (default `[]`) — "Additional ignore file paths to
  respect. **These files take precedence over .geminiignore and .gitignore.**" Earlier entries win.
- `context.fileFiltering.enableRecursiveFileSearch` (default `true`)

Note the wording is consistently "**when searching**". `.geminiignore` docs likewise say it
excludes paths "from tools that support this feature" and give `@`-mention as the example
(<https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/gemini-ignore.md>).
**Nothing in the primary docs claims `.geminiignore` blocks `run_shell_command`.** Assume it does
not; use a policy `deny` rule for that.

**Tools**
- `tools.core` (array) — "Restrict the set of built-in tools with an **allowlist**."
- `tools.allowed` (array) — "Tool names that **bypass the confirmation dialog**", e.g.
  `["run_shell_command(git)", "run_shell_command(npm test)"]`. This is a *loosening* setting —
  flag broad entries.
- `tools.confirmationRequired` (array) — "Tool names that **always require user confirmation**.
  Takes precedence over allowed tools and core tool allowlists." This is the settings-level
  hardening knob.
- `tools.exclude` (array) — "Tool names to exclude from discovery." **Deprecated** in favour of
  policy `deny` (policy-engine doc).

**Sandbox**
- `tools.sandbox` — "Legacy full-process sandbox execution environment… boolean… string path to a
  sandbox profile, or… explicit sandbox command (e.g., `docker`, `podman`, `lxc`,
  `windows-native`)."
- `tools.sandboxAllowedPaths` (array, default `[]`) — extra paths the sandbox may access.
- `tools.sandboxNetworkAccess` (boolean, **default `false`**) — network denied by default inside
  the sandbox.
- `security.toolSandboxing` (boolean, default `false`) — "Tool-level sandboxing. Isolates
  individual tools instead of the entire CLI process." (Newer than `tools.sandbox`.)

Env vars for the process sandbox (<https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md>):
`GEMINI_SANDBOX` (`true|docker|podman|sandbox-exec`), `SEATBELT_PROFILE`
(`permissive-open` default / `permissive-closed` / `permissive-proxied` / `restrictive-open` /
`restrictive-closed`), `SANDBOX_FLAGS`, `SANDBOX_SET_UID_GID`. CLI flag `--sandbox` / `-s`.
The sandbox "restrict[s] writes outside project directory". **For secret-read protection you want
`restrictive-closed` (max restrictions, no network) or a container — the default
`permissive-open` allows network.**

**Security**
- `security.disableYoloMode` (default `false`) — "Disable YOLO mode, even if enabled by a flag."
- `security.disableAlwaysAllow` (default `false`) — kills "Always allow" in confirmation dialogs.
- `security.enablePermanentToolApproval` (default `false`)
- `security.autoAddToPolicyByDefault` (default `false`)
- `security.blockGitExtensions` (default `false`); `security.allowedExtensions` (regex allowlist,
  overrides `blockGitExtensions`)
- `security.folderTrust.enabled` (**default `true`** per the config reference)

**Environment variable redaction — the standout feature**
- `security.environmentVariableRedaction.enabled` (boolean, **default `false`**) — "Enable
  redaction of environment variables that may contain secrets."
- `security.environmentVariableRedaction.blocked` (array, default `[]`) — always redact
- `security.environmentVariableRedaction.allowed` (array, default `[]`) — bypass redaction

This is **off by default**. Turning it on is the single highest-value settings change for
env-var leakage. Note the setting name says "may contain secrets", implying heuristic detection —
I could not find documentation of the heuristic. **[UNVERIFIED: exact redaction heuristic and
what it covers beyond env vars.]**

**MCP**
- `mcp.allowed` (array) / `mcp.excluded` (array) — server-level allow/deny.
- `mcpServers.<NAME>`: `command`, `args`, `url` (SSE), `httpUrl` (streamable HTTP), `env`,
  `trust` (boolean — "**Trust this server and bypass all tool call confirmations**"),
  `includeTools`, `excludeTools` ("`excludeTools` takes precedence").
- `admin.mcp.enabled` (if false, disallows MCP entirely), `admin.mcp.config` (admin allowlist),
  `admin.mcp.requiredConfig` (always injected).

`"trust": true` on an MCP server is an audit red flag — it bypasses all confirmation.

**Hooks** (repo-relevant and dangerous)
- `hooksConfig.enabled` (canonical toggle — "When disabled, no hooks will be executed"),
  `hooksConfig.disabled` (array), `hooksConfig.notifications`.
- `hooks.BeforeTool`, `AfterTool`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `AfterModel`,
  `BeforeToolSelection`, `SessionStart`, `SessionEnd`, `PreCompress`, `Notification`
  (<https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md>).

Hooks run **synchronous arbitrary programs** in the agent loop. Because `.gemini/settings.json`
is a project file that **overrides user settings**, a hostile repo can register a `SessionStart`
hook that exfiltrates. Folder Trust (§B.4) is the mitigation. Defensively, hooks are also the
mechanism for a *custom* secret scanner (`BeforeTool` returning `{"decision": "deny"}` at exit 0,
or exit 2 for a hard block).

### B.4 Folder Trust (the out-of-repo / hostile-repo control)

<https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md>

Enable in user `settings.json`:

```json
{ "security": { "folderTrust": { "enabled": true } } }
```

Trust decisions stored in `~/.gemini/trustedFolders.json`; manage via `/permissions`.
In an **untrusted** folder the CLI:

1. "will **not** load the `.gemini/settings.json` file from the project"
2. does not load project `.env` files
3. blocks extension install/update/removal
4. "You will always be prompted before any tool is run"
5. skips auto-loading memory files from local settings

Escape hatches to be aware of: `GEMINI_CLI_TRUST_WORKSPACE=true` "trusts the current workspace
for the duration of the session, bypassing the folder trust check", and
`GEMINI_CLI_TRUSTED_FOLDERS_PATH` relocates the trust store
(<https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md>).

### B.5 Enterprise admin controls

<https://github.com/google-gemini/gemini-cli/blob/main/docs/admin/enterprise-controls.md>

"Enterprise Admin Controls are enforced globally and cannot be overridden by users locally."
Managed at <https://goo.gle/manage-gemini-cli>. Controls: **Strict Mode** (default *enabled* —
"users will not be able to enter yolo mode"), **Extensions** (default disabled), **MCP** (default
disabled), **MCP Servers allowlist** (preview) and **Required MCP Servers** (preview).

Allowlist enforcement is strict: "If the allowlist contains one or more servers, **all locally
configured servers not present in the allowlist are ignored**", `url`/`type`/`trust` are taken
from the admin list, and the client "automatically clears local execution fields (`command`,
`args`, `env`, `cwd`, `httpUrl`, `tcp`)". That last clause specifically kills the
"MCP `env` block as exfil channel" pattern.

The doc also distinguishes these from system settings files, which "can still be modified by users
with sufficient privileges" — admin controls are "immutable at the local level".

### B.6 Training / data retention by auth method

<https://google-gemini.github.io/gemini-cli/docs/tos-privacy.html>

| Auth | Prompts/code collected & used to improve models |
|---|---|
| Google account, individual (free Gemini Code Assist) | **Yes** — "Your prompts, answers, and related code are collected" |
| Google account, Standard/Enterprise Code Assist | **No** — inputs treated as confidential |
| Gemini API key, **unpaid** tier | **Yes** |
| Gemini API key, **paid** tier | **No** — logs kept "a limited period of time, solely for the purpose of detecting violations of the Prohibited Use Policy" |
| Vertex AI GenAI API | **No** — inputs confidential, never collected |

Opt-out: `privacy.usageStatisticsEnabled` (**default `true`**;
<https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md>).
Per the ToS page, on the individual/unpaid tiers this single toggle disables **both** telemetry and
prompt/code collection; on paid/enterprise tiers it disables telemetry only (prompts were never
collected). Separately: `telemetry.enabled` / `telemetry.target` (`local`|`gcp`) /
`telemetry.otlpEndpoint` / `telemetry.outfile`, overridable by `GEMINI_TELEMETRY_*` env vars.

**Practical rule: free personal Google account = your repo contents train Google's models. If a
repo has secrets, the auth method is part of the threat model.**

### B.7 Known gaps (Gemini CLI)

| Gap | Evidence |
|---|---|
| **Workspace-tier policies do not work** — repo-committed `.gemini/policies/*.toml` is inert | policy-engine.md warning + issue #18186 |
| `.geminiignore` / `respectGitIgnore` are described as "when **searching**"; no claim they gate `run_shell_command` | gemini-ignore.md, configuration.md |
| Env-var redaction is **off by default** | `security.environmentVariableRedaction.enabled` default `false` |
| Sandbox is off by default; default seatbelt profile `permissive-open` **allows network** | sandbox.md |
| Project `.gemini/settings.json` **overrides user settings** — hostile repo can loosen, and register hooks | configuration.md, hooks/index.md |
| MCP server names containing `_` make wildcard security rules "fail silently" | policy-engine.md warning |
| `GEMINI_CLI_TRUST_WORKSPACE=true` bypasses folder trust | configuration.md |
| `tools.exclude` deprecated but still widely copy-pasted; gives weaker guarantees than policy `deny` | policy-engine.md |
| Free-tier auth trains on your code | tos-privacy |

### B.8 Detection checklist — Gemini CLI

Repo-side (`.gemini/`):
- [ ] `.geminiignore` exists and covers `.env*`, `*.pem`, `*.key`, `id_rsa*`, `.netrc`, `.npmrc`,
      `secrets/`. (Search-scope only — note as weak.)
- [ ] `.gemini/settings.json` present? Check it does **not** set: `tools.sandbox: false`,
      `tools.sandboxNetworkAccess: true`, broad `tools.allowed` (esp. bare `run_shell_command`),
      `security.disableYoloMode: false`, `security.folderTrust.enabled: false`,
      `privacy.usageStatisticsEnabled: true` where the org wants it off.
- [ ] `.gemini/settings.json` `hooks.*` / `hooksConfig.enabled` — **any repo-registered hook is
      arbitrary code execution at session start**. Flag loudly.
- [ ] `.gemini/settings.json` `mcpServers.*.trust: true` → bypasses all confirmations. Flag.
- [ ] `.gemini/settings.json` `mcpServers.*.env` / `headers` containing `$VAR` / `${VAR}`
      substitution to a remote `url`/`httpUrl` → exfil primitive.
- [ ] `.gemini/policies/*.toml` present → note it is **currently inert** (issue #18186); the repo
      *looks* hardened but isn't.
- [ ] `.gemini/sandbox.Dockerfile` / `.gemini/sandbox-macos-custom.sb` — read them; a custom
      profile can be weaker than the built-in.
- [ ] `context.fileFiltering.customIgnoreFilePaths` — takes precedence over `.geminiignore`;
      check what it points at.

Machine-side (report as "not repo-enforceable, needs user/admin config"):
- [ ] `~/.gemini/policies/*.toml` with `deny` rules for credential reads and `env`/`printenv` shell.
- [ ] `~/.gemini/settings.json`: `security.environmentVariableRedaction.enabled: true`,
      `security.disableYoloMode: true`, `security.disableAlwaysAllow: true`,
      `security.folderTrust.enabled: true`, `tools.sandbox` set, `tools.sandboxNetworkAccess: false`,
      `privacy.usageStatisticsEnabled: false`, `mcp.allowed` non-empty.
- [ ] Auth method is paid API key / Vertex / Workspace, not a free personal Google account.
- [ ] No `GEMINI_CLI_TRUST_WORKSPACE=true` in shell profiles or CI.
- [ ] No `--yolo` / `--approval-mode yolo` in scripts, Makefiles, or CI workflows.

---

## C. Cursor + GitHub Copilot

### C.1 Cursor — ignore files

<https://cursor.com/docs/context/ignore-files>

`.cursorignore` "blocks access to files listed in `.cursorignore` from: Code accessible by Agent,
Tab, and Inline Edit" and "Code accessible via @ mention references."

**The documented hole, verbatim:** "The terminal and MCP server tools used by Agent cannot block
access to code governed by `.cursorignore`." Plus: "While Cursor blocks ignored files, complete
protection isn't guaranteed due to LLM unpredictability."

So `.cursorignore` stops the read/edit tools and @-mentions, **not** `cat .env` in the agent
terminal and **not** an MCP server that reads the filesystem.

`.cursorindexingignore` is the indexing-only variant (excluded from the codebase index but still
agent-accessible). Cursor also ships a **default** ignore list including `**/.env*`, lock files,
binaries, `node_modules/`, `.git/`. **Hierarchical ignore** (walking parent dirs for
`.cursorignore`) is a setting; per the docs, "Starting in Cursor 3.11, this setting moves to
`Cursor Settings` > `Indexing` > `Ignore Files`." Negation follows gitignore semantics — a file
under an excluded parent directory cannot be re-included.

`.cursorignore` is repo-committable and is itself write-protected by the sandbox (§C.3).

### C.2 Cursor — permissions and run modes

Two separate permission systems; do not conflate them.

**(a) IDE agent — `permissions.json`** (<https://cursor.com/docs/reference/permissions>)

Locations, both optional: `~/.cursor/permissions.json` (per-user) and
`<workspace>/.cursor/permissions.json` (**per-repo, committable**). Fields:

- `mcpAllowlist` (`string[]`) — `server:tool` syntax, case-insensitive; `my-server:my_tool`,
  `my-server:*`, `*:my_tool`, `*:*`, and globs within names (`my-server:list_*`).
- `terminalAllowlist` (`string[]`) — **prefix-based, case-sensitive**; `git` matches anything
  starting with `git`; `npm:install*` separates base command from arg globs.
- `autoRun.allow_instructions` / `autoRun.block_instructions` (`string[]`) — **natural-language**
  steering hints for the Auto-review classifier, e.g. `"Every AWS CLI command should go through
  approval first."` (example from <https://cursor.com/docs/agent/security/run-modes>).

Precedence: team admin dashboard > `permissions.json` (per-user + per-repo **concatenated**) >
IDE settings UI. When `permissions.json` defines a field it "fully replaces" the IDE allowlist for
that type, and the IDE UI becomes read-only. An empty array after concatenation = empty allowlist,
with no IDE fallback. Only active when a Run Mode is enabled.

Explicit disclaimer: "Allowlists and autoRun instructions are **best-effort convenience**" — not a
security guarantee.

Note there are **allowlists only, no denylist**, for terminal/MCP in `permissions.json`. Blocking
is expressed as natural-language `block_instructions` handed to a classifier. That is a
fundamentally weaker primitive than a regex/glob deny rule and should be scored as such.

**Run Modes** (<https://cursor.com/docs/agent/security/run-modes>):
- **Auto-review** (recommended) — "Allowlisted calls run immediately. Other shell commands run in
  the sandbox when possible."
- **Allowlist** — "Actions in your allowlist run without approval."
- **Run Everything** — "Every tool call runs automatically", no sandboxing, no classifier. This is
  Cursor's YOLO equivalent.

The Auto-review classifier evaluates MCP tool calls alongside shell and Fetch.

**(b) Cursor CLI — `permissions` tokens**
(<https://cursor.com/docs/cli/reference/permissions>,
<https://cursor.com/docs/cli/reference/configuration>)

Global `~/.cursor/cli-config.json`; project `<project>/.cursor/cli.json` (**permissions only**,
committable). Token types: `Shell(commandBase)`, `Read(pathOrGlob)`, `Write(pathOrGlob)`,
`WebFetch(domainOrPattern)`, `Mcp(server:tool)`. **Deny rules take precedence over allow rules.**
Globs use `**`, `*`, `?`. Relative paths are workspace-scoped; absolute paths target external
files. WebFetch patterns: `*` (all), `*.example.com` (subdomains), `example.com` (exact only).

Hardened `<project>/.cursor/cli.json`:

```json
{
  "version": 1,
  "permissions": {
    "allow": ["Shell(git status)", "Shell(git diff)", "Shell(npm test)", "Read(src/**)"],
    "deny": [
      "Read(.env*)", "Read(**/.env*)", "Read(**/*.pem)", "Read(**/*.key)",
      "Read(**/id_rsa*)", "Read(**/.netrc)", "Read(**/.npmrc)",
      "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.config/gcloud/**)", "Read(~/.kube/**)",
      "Shell(env)", "Shell(printenv)", "Shell(curl)", "Shell(wget)",
      "Shell(rm)", "Shell(aws)", "Shell(gcloud)",
      "WebFetch(*)"
    ]
  }
}
```

Approval modes for the CLI: `allowlist`, `auto-review`, `unrestricted`
(<https://cursor.com/docs/cli/reference/configuration>).

### C.3 Cursor — sandbox (`sandbox.json`)

<https://cursor.com/docs/reference/sandbox>

Locations: `~/.cursor/sandbox.json` (user, lower priority) and
`<workspace>/.cursor/sandbox.json` (**repo, higher priority**). Merge order:
`per-user < per-repo < team-admin < hardcoded security rules`. Paths union; network allow lists
union unless a team-admin policy replaces them; deny lists always union; restrictive settings win.

Fields:

| Field | Default | Meaning |
|---|---|---|
| `type` | `"workspace_readwrite"` | also `"workspace_readonly"`, `"insecure_none"` |
| `additionalReadwritePaths` | `[]` | extra RW paths |
| `additionalReadonlyPaths` | `[]` | extra RO paths |
| `disableTmpWrite` | `false` | blocks default `/tmp` write |
| `enableSharedBuildCache` | `false` | shares npm/cargo/pip caches |
| `networkPolicy.default` | `"deny"` | or `"allow"` |
| `networkPolicy.allow` | — | exact domain, `*.example.com`, or CIDR |
| `networkPolicy.deny` | — | always blocks, overrides allow |

RFC 1918 ranges (`10.x`, `172.16.x`, `192.168.x`, `127.x`), IPv6 private ranges, and the cloud
metadata endpoint `169.254.169.254` are **blocked by default to prevent SSRF**. That is a
meaningful anti-exfil default — it kills the classic IMDS credential grab.

Always write-protected regardless of config: `.cursor/*.json`, `.cursor/**/*.json`,
`.cursor/.workspace-trusted`, `.claude/*.json`, `.claude/**/*.json`, `.vscode/**`,
`.code-workspace`, `.git/hooks/**`, `.git/config`, `.git/info/attributes`, `.cursorignore`.
Writable `.cursor` subdirs: `rules/`, `commands/`, `worktrees/`, `skills/`, `agents/`.

> ⚠️ **Documented gap, verbatim from the sandbox reference:**
> "SSL certificates and `~/.ssh` remain readable."
>
> So Cursor's sandbox does **not** protect SSH private keys from a sandboxed command. Combined
> with `.cursorignore` not covering the terminal, **`cat ~/.ssh/id_rsa` is not blocked by either
> mechanism.** The only stop is a `Read(~/.ssh/**)` deny in the CLI permissions, or an
> `autoRun.block_instructions` hint (classifier, best-effort), or human approval. Flag this
> explicitly in any hardening report.

Run-modes doc adds that the sandbox protects `.git/config`, `.git/hooks`, `.vscode`,
`.cursorignore` "and sensitive Cursor config files", and that "Users cannot weaken these hardcoded
protections locally" (<https://cursor.com/docs/agent/security/run-modes>).

### C.4 Cursor — cloud agents, network, privacy

<https://cursor.com/docs/cloud-agent/security-network>

Three secret types: **Environment Variables** (visible to the agent; for non-sensitive config),
**Runtime Secrets** (formerly "Redacted Secrets" — "their contents are redacted from the agent's
tool call results, chat transcript, commits, and commit messages", *but* "users accessing the
terminal environment can still view them"), **Build Secrets** (Docker build only, never available
to the running agent). All encrypted at rest and in transit.

Network modes: allow all / default + allowlist / allowlist only. Configurable at user,
environment, and team level; Enterprise can lock org-wide. The docs warn against wildcarding
artifact-upload allowlists because that "creates an exfiltration path for a prompt-injected
agent." Egress IPs published at `cursor.com/docs/ips.json`.

**Privacy Mode** (<https://cursor.com/data-use>,
<https://cursor.com/docs/enterprise/privacy-and-data-governance>): when enabled, customer data is
not used for training by Cursor; Cursor states ZDR agreements with providers; cached file contents
are temporary and never used as training data. Caveats: providers "may run risk classifiers", and
data triggering abuse detectors may be stored for investigation; non-ZDR models are designated as
such and require admin opt-in. Privacy Mode can be enforced team-wide and is **on by default for
Enterprise**.

Cursor's overall agent-security stance (<https://cursor.com/docs/agent/security>): terminal
commands require approval by default; "Agents cannot make arbitrary network requests with default
settings" (restricted to GitHub, direct link retrieval, web search providers); Run Modes are
"best-effort guardrails rather than a hard security boundary."

### C.5 Cursor — known gaps

| Gap | Evidence |
|---|---|
| `.cursorignore` does **not** block the agent terminal or MCP tools | ignore-files doc, verbatim |
| Sandbox leaves `~/.ssh` and SSL certs **readable** | sandbox reference |
| `permissions.json` has allowlists only; blocking is natural-language hints to a classifier | permissions reference |
| Vendor labels the whole thing best-effort, not a boundary | agent/security, permissions reference |
| `terminalAllowlist` is **prefix** matching — `git` allows `git config --global core.pager 'sh -c ...'` | permissions reference |
| Runtime Secrets are redacted from transcripts but readable from the terminal | cloud-agent security-network |
| `permissions.json` "fully replaces" IDE allowlists — a repo file can silently override careful IDE settings (they concatenate with per-user, so a repo can only *add*, but adding is enough to widen) | permissions reference |
| "Run Everything" mode disables sandboxing and classifier entirely | run-modes |

### C.6 GitHub Copilot — content exclusion

<https://docs.github.com/en/copilot/concepts/context/content-exclusion>,
<https://docs.github.com/en/copilot/how-tos/configure-content-exclusion/exclude-content-from-copilot>

**Not a repo file.** Configured in **Settings → Copilot → Content exclusion** at repository,
organization, or enterprise level. Repo admins, org owners, enterprise owners can edit; the
"Maintain" role can view only.

Syntax (in the "Repositories and paths to exclude" box):

```yaml
# files anywhere
"*":
  - "/path/to/file"

# files in a specific repo
REPOSITORY-REFERENCE:
  - "/PATH/TO/DIRECTORY/OR/FILE"
  - "/PATH/TO/DIRECTORY/OR/FILE"
```

**Coverage is the problem.** Verbatim limitations:

> "It's possible that Copilot may use semantic information from an excluded file if the information
> is provided by the IDE indirectly. Examples of such content include type information and
> hover-over definitions for symbols used in code, as well as general project properties such as
> build configuration information. Currently, content exclusions do not apply to symbolic links
> (symlinks) and repositories located on remote filesystems."

And: **"Content exclusion is currently not supported in Edit and Agent modes of Copilot Chat in
Visual Studio Code and other editors."** Supported for inline suggestions in VS/VS Code/JetBrains/
Vim/Neovim/Xcode/Eclipse, and for Chat in VS/VS Code/JetBrains/github.com/GitHub Mobile; not
supported for Xcode Chat, Eclipse Chat, or Azure Data Studio.

The concepts page does **not** list Copilot CLI or the Copilot coding agent as supported.
**[UNVERIFIED — absence from the support table is not an explicit "not supported" statement for
coding agent / CLI. Treat content exclusion as providing no agent-mode protection until GitHub
says otherwise.]**

There is no `.github/copilot` content-exclusion *file* and no `copilot.exclude` repo key that I
could find in primary docs — the mechanism is settings-UI only. **[UNVERIFIED that no such file
exists; I found no doc for one.]**

### C.7 Copilot coding agent — firewall

<https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/customize-the-agent-firewall>

Managed under **Settings → Copilot → Internet access**, at org level (`Enabled` / `Disabled` /
`Let repositories decide`) and repo level (toggle, only if org says "let repositories decide").
Two independent switches: **Enable firewall** and **Recommended allowlist**.

Verbatim warning: **"Disabling the firewall will allow Copilot to connect to any host, increasing
risks of exfiltration of code or other sensitive information."**

Historical Actions variables `COPILOT_AGENT_FIREWALL_ALLOW_LIST` (replaces the default list,
comma-separated hosts) and `COPILOT_AGENT_FIREWALL_ALLOW_LIST_ADDITIONS` (adds to it) are
referenced in search-surfaced docs; the current firewall page says only that "Previous
configurations saved as Actions variables will be maintained", implying the UI has superseded
them. **[Partially verified — the variables are real but appear legacy as of 2026-08.]**

The default recommended allowlist is documented at
<https://docs.github.com/en/copilot/reference/copilot-allowlist-reference>. Note the firewall is
**incompatible with self-hosted and Windows runners** — you must disable it there
(<https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment>),
which is a real hardening trade-off. Environment customization is via `copilot-setup-steps.yml`
(runner, permissions, services, ≤59 min timeout), same doc.

### C.8 Copilot CLI — permissions (this one *is* partly repo-committable)

Config dir: `~/.copilot` (or `COPILOT_HOME`, or `--config-dir=DIRECTORY`)
(<https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference>).
Files: `settings.json` (user-editable, JSONC), `config.json` (auto-managed state — do not edit),
`permissions-config.json`, `mcp-config.json`, `lsp-config.json`, `copilot-instructions.md`.

**Settings cascade (verbatim ordering):**
1. Built-in defaults
2. MDM managed settings
3. User settings — `~/.copilot/settings.json`
4. **Repository settings — `.github/copilot/settings.json`** ← committable
5. **Local settings — `.github/copilot/settings.local.json`** ← should be gitignored
6. Environment variables
7. Command-line flags

Notable settings keys (same doc):

| Setting | Type | Default | Purpose |
|---|---|---|---|
| `allowedUrls` | `string[]` | `[]` | "URLs or domains allowed without prompting. Supports exact URLs, domain patterns, and wildcard subdomains" |
| `deniedUrls` | `string[]` | `[]` | always denied; **denial takes precedence** |
| `sandbox.enabled` | boolean | `false` | "Restrict commands to sandboxed environment" |
| `permissions.disableBypassPermissionsMode` | string | — | set to `"disable"` to **suppress allow-all flags** |
| `askUser` | boolean | `true` | agent may ask clarifying questions |
| `autoUpdate` | boolean | `true` | |

`permissions.disableBypassPermissionsMode: "disable"` is the key hardening knob — it neuters
`--allow-all` / `--yolo`. Setting it in `.github/copilot/settings.json` makes it repo-enforced
(subject to the cascade: env vars and CLI flags still sit *above* repo settings in the ordering,
so verify empirically). **[UNVERIFIED whether `disableBypassPermissionsMode` set at repo level
survives a CLI `--yolo`; the cascade table implies flags win, but the setting's stated purpose
implies it should not.]**

**`permissions-config.json`** stores *saved approvals* per location
(<https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference>):

```json
{
  "locations": {
    "/absolute/path/to/repo": {
      "tool_approvals": [
        { "kind": "commands", "commandIdentifiers": ["git:*"] },
        { "kind": "write" },
        { "kind": "mcp", "serverName": "github-mcp-server", "toolName": null }
      ],
      "allowed_directories": ["/absolute/directory/paths"]
    }
  }
}
```

Approval `kind` values: `commands` (needs `commandIdentifiers`), `read`, `write`, `mcp`
(`serverName` + `toolName`, `null` = all tools on that server), `mcp-sampling`, `memory`,
`custom-tool`, `extension-management`, `extension-permission-access`.

Command matching is literal except for a trailing `:*`: `git status` matches only `git status`
(not `git status --short`); `git:*` matches `git`, `git status`, `git push` but **not** `gitea`;
`gh pr:*` matches `gh pr view` but not `gh repo view`. `allowed_directories` must be absolute,
symlinks resolved, case-insensitive on Windows, UNC paths blocked unless extended-length.

This file is a **grant store, not a policy file** — it only ever *widens*. A committed or
inherited `permissions-config.json` with `{"kind":"write"}` or `{"kind":"mcp","toolName":null}`
is a finding.

**Session flags** (<https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools>):
`--allow-tool` / `--deny-tool` take `Kind(argument)` patterns, e.g.
`copilot --allow-tool 'shell(git:*)' --deny-tool 'shell(git push)'`, and
`--deny-tool='My-MCP-Server(tool_name)'`. **"Deny rules always take precedence over allow rules,
even when `--allow-all` is set or a matching approval has been saved in
`permissions-config.json`."** These flags are session-only and are not written to
`permissions-config.json` (URL domain approvals are the exception — they persist to `allowedUrls`
in `settings.json`).

Permissive flags: `--allow-all-tools`, `--allow-all` / `--yolo`. Verbatim warning: **"It is
strongly recommended that you only use these options in an isolated environment. You should never
use an alias to apply one of these options every time you start Copilot CLI."**
`/reset-allowed-tools` revokes session permissions and clears saved approvals for the location.

**Sandbox** (<https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/configuring-local-sandbox-settings>):
under the `sandbox` key in `settings.json`; powered by Microsoft eXecution Container (MXC) —
Seatbelt on macOS, Bubblewrap on Linux, ProcessContainer on Windows. By default Copilot gets
read/write on everything at and below CWD; unselecting "Include working directory" blocks `.git`
access; individual paths can be marked Denied; network can be fully isolated or restricted to
block local network; macOS **keychain access is off by default**. The doc does not enumerate the
JSON keys — it directs you to `copilot help sandbox`. **[UNVERIFIED: exact `sandbox.*` key names
beyond `sandbox.enabled`. Run `copilot help sandbox` to enumerate.]**

Copilot CLI also reads `.claude/settings.json` and `.claude/settings.local.json` for a shared
cross-tool subset (`companyAnnouncements`, `disableAllHooks`, `enabledPlugins`,
`extraKnownMarketplaces`, `hooks`) — so **`.claude/settings.json` in a repo affects Copilot CLI
too**, including hooks. Worth flagging in a cross-harness scan.

Trusted folders live in `config.json` under a `trustedFolders` array
(<https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/configure-copilot-cli>).

### C.9 Detection checklist — Cursor

- [ ] `.cursorignore` exists at repo root and covers `.env*`, `*.pem`, `*.key`, `id_rsa*`,
      `.netrc`, `.npmrc`, `secrets/`, `credentials*`, `*.tfstate`, `*.kdbx`.
      **Annotate: does not cover the agent terminal or MCP.**
- [ ] `.cursorindexingignore` distinguished from `.cursorignore` (indexing-only — weaker).
- [ ] `<repo>/.cursor/cli.json` exists with `permissions.deny` entries for
      `Read(.env*)`, `Read(~/.ssh/**)`, `Read(~/.aws/**)`, `Shell(env)`, `Shell(printenv)`,
      `Shell(curl)`, `Shell(wget)`, and a restrictive `WebFetch(...)`.
      **This is the only Cursor mechanism with true deny-precedence — its absence is the headline
      finding.**
- [ ] `<repo>/.cursor/permissions.json` — check `terminalAllowlist` isn't broad (bare `git`,
      `bash`, `sh`, `python`, `node`, `npm`, `docker` are all escape hatches via subcommands);
      check `mcpAllowlist` has no `*:*`.
- [ ] `<repo>/.cursor/sandbox.json` exists with `"networkPolicy": {"default": "deny"}` and a
      minimal `allow` list; `type` is not `"insecure_none"`; `additionalReadwritePaths` /
      `additionalReadonlyPaths` do not include `~`, `/`, `~/.ssh`, `~/.aws`.
- [ ] `autoRun.block_instructions` mentions credentials/env/network — weak, but shows intent.
- [ ] **Anti-pattern:** any doc/README/script instructing users to enable "Run Everything" mode.
- [ ] Privacy Mode: cannot be detected from the repo. Report as "verify in Cursor Settings /
      team dashboard; on by default for Enterprise."
- [ ] Note explicitly: **Cursor's sandbox leaves `~/.ssh` readable** — deny it in `cli.json`.

### C.10 Detection checklist — GitHub Copilot

Repo-visible:
- [ ] `.github/copilot/settings.json` exists and sets
      `permissions.disableBypassPermissionsMode: "disable"`, `sandbox.enabled: true`,
      a non-empty `deniedUrls`, and a tight `allowedUrls` (no bare `*`).
- [ ] `.github/copilot/settings.local.json` is in `.gitignore` (it's the personal-override layer).
- [ ] `.github/workflows/copilot-setup-steps.yml` — review installed tooling and `permissions:`
      block; over-broad `GITHUB_TOKEN` permissions here are a finding.
- [ ] No committed `permissions-config.json` and no `mcp-config.json` granting
      `{"kind":"mcp","toolName":null}` or `{"kind":"write"}` blanket approvals.
- [ ] `.claude/settings.json` hooks — **also consumed by Copilot CLI**; check `disableAllHooks`.
- [ ] No repo docs/aliases/CI invoking `copilot --allow-all`, `--yolo`, or `--allow-all-tools`
      (GitHub explicitly warns against aliasing these).
- [ ] `.gitignore` covers secret patterns (content exclusion is settings-side; gitignore is the
      only repo-visible signal).

Not repo-visible — must be reported as "verify in GitHub settings":
- [ ] Repo/org **Copilot → Content exclusion** configured for secret paths.
      **Caveat: does not apply to Edit/Agent modes of Copilot Chat; no documented coverage for
      Copilot CLI or the coding agent.**
- [ ] Repo/org **Copilot → Internet access**: firewall **Enabled** and recommended allowlist
      **Enabled**. Disabling it "increas[es] risks of exfiltration of code or other sensitive
      information."
- [ ] If self-hosted or Windows runners are used, the firewall is necessarily off — compensating
      network controls needed.

---

## D. Aider, Cline / Roo Code, Amp, Kiro

### D.1 Aider

Docs: <https://aider.chat/docs/config/options.html>

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--aiderignore AIDERIGNORE` | `AIDER_AIDERIGNORE` | `.aiderignore` in git root | "Specify the aider ignore file" |
| `--no-auto-commits` | `AIDER_AUTO_COMMITS` | auto-commits **on** | disables automatic committing of LLM changes |
| `--no-gitignore` | `AIDER_GITIGNORE` | on | disables "adding `.aider*` to `.gitignore`" |
| `--subtree-only` | `AIDER_SUBTREE_ONLY` | `false` | "Only consider files in the current subtree of the git repository" |
| `--analytics-disable` | `AIDER_ANALYTICS_DISABLE` | `false` | "Permanently disable analytics" |
| `--yes-always` | `AIDER_YES_ALWAYS` | — | "Always say yes to every confirmation" — **the YOLO flag** |
| `--read FILE` | `AIDER_READ` | — | read-only file |

Aider config is committable as `.aider.conf.yml` (project root) and `.aiderignore`.
**[UNVERIFIED: `.aider.conf.yml` precedence rules — I did not fetch that page.]**

**Known gaps:** Aider's option reference "contains no sandboxing or permission-restriction options
beyond read-only file specification." `.aiderignore` scopes which files Aider *adds to the chat /
repo map*; it is not an access-control boundary, and Aider's shell/command execution is not gated
by it. `--yes-always` in a script is a total bypass. Treat Aider as an *unsandboxed* harness.

**Detection checklist — Aider:**
- [ ] `.aiderignore` present, covering `.env*`, `*.pem`, `*.key`, `secrets/`.
- [ ] `.aider.conf.yml` sets `auto-commits: false` and `analytics-disable: true`.
- [ ] `subtree-only: true` if the repo is a monorepo subtree.
- [ ] **Anti-pattern:** `--yes-always` / `yes-always: true` anywhere in scripts, Makefiles, CI.
- [ ] `.gitignore` includes `.aider*` (Aider adds it by default unless `--no-gitignore`).

### D.2 Cline

Docs: <https://docs.cline.bot/customization/clineignore>,
<https://docs.cline.bot/features/auto-approve>

`.clineignore` is repo-root, gitignore-syntax, per-workspace-root in monorepos. Cline's own docs
now mark it **"(deprecate soon)"** and state it "filters what Cline loads automatically, but it is
**not a security or access-control boundary** — ignored files can still be read via explicit
`@` mentions or shell commands." It "guards file reads/edits (`read_files`, editor, `apply_patch`)
— it does not filter `search_files`/`list_files` results or guard shell commands."

Auto-approve settings (Cline Settings → Features), eight toggles: Read project files, Read all
files, Edit project files, Edit all files, Execute safe commands, Execute all commands, Use the
browser, Use MCP servers. Note that "Read all files" / "Edit all files" explicitly extend **beyond
the workspace** — those two are the out-of-repo escape and should always be off.

Command safety is **model-judged, not list-based**: "The model marks each command with a
`requires_approval` flag based on the command and arguments." That means a prompt-injected model
can mark a malicious command as safe. **YOLO Mode** auto-approves everything (files, terminal,
browser, MCP, mode transitions).

Storage location for auto-approve settings is not documented on that page. **[UNVERIFIED: whether
auto-approve state is repo-committable. It appears to be VS Code extension global state, i.e. not
repo-committable.]**

**Detection checklist — Cline:**
- [ ] `.clineignore` present (note: deprecating, and explicitly not a security boundary).
- [ ] `.clinerules` / `.clinerules/` reviewed — rules are model instructions, not enforcement.
- [ ] Report as not-repo-verifiable: "Read all files" and "Edit all files" toggles are OFF;
      "Execute all commands" is OFF; YOLO Mode is OFF.
- [ ] Flag any repo docs telling users to enable YOLO Mode.

### D.3 Roo Code

Docs: <https://roocodeinc.github.io/Roo-Code/features/rooignore>

`.rooignore` uses gitignore syntax. Enforcement:

- `read_file` — "Will not read ignored files"
- `write_to_file` — "Will not write to or create new ignored files"
- `apply_diff` — "Will not apply diffs to ignored files"
- `list_files` / `@directory` — filtered or marked with 🔒
- Single-file mentions return `(File is ignored by .rooignore)`
- **`execute_command` IS partially guarded** — "checks if a command (from a predefined list like
  `cat` or `grep`) targets an ignored file. If so, execution is blocked."

**This makes Roo the only harness in this document that attempts to gate shell reads via its
ignore file.** But the docs are candid about the limits: "Protection for `execute_command` is
limited to a predefined list of file-reading commands. Custom scripts or uncommon utilities might
not be caught." And: "`.rooignore` is a powerful tool for controlling Roo's file access via its
tools, but it does not create a system-level sandbox." Scope is the VS Code workspace root only.
Roo cannot modify `.rooignore` itself.

Roo has granular auto-approve settings analogous to Cline's
(<https://roocodeinc.github.io/Roo-Code/features/auto-approving-actions/>).

**Detection checklist — Roo Code:**
- [ ] `.rooignore` present, covering `.env*`, `*.pem`, `*.key`, `id_rsa*`, `secrets/`.
- [ ] Note the partial `execute_command` guard as a *plus* relative to peers, but flag that
      `python -c`, `base64`, `xxd`, `head`, `perl -ne`, custom scripts bypass it.
- [ ] `.roo/` rules reviewed.
- [ ] Report as not-repo-verifiable: auto-approve toggles for command execution and out-of-workspace
      read/write are off.

### D.4 Amp

Docs: <https://ampcode.com/security>, <https://ampcode.com/news/tool-level-permissions>,
<https://ampcode.com/news/mcp-permissions>

Permissions live under the `amp.permissions` key in Amp settings (editable via
"Amp: Edit User Permissions" in VS Code). Rule shape:

- `tool` — which tool (e.g. `"Bash"`, `"mcp__*"`, `"*"`)
- `matches` — optional argument matcher, e.g. `{ "cmd": "*git commit*" }` or
  `{ "cmd": ["*python *", "*python3 *"] }`
- `action` — `"allow"` | `"ask"` | `"reject"` | `"delegate"`
- `to` — with `delegate`, "a permission helper (must be on `$PATH`)"

`amp.mcpPermissions` defines rules that block or allow MCP servers.

**Standout feature: automatic secret redaction.** Amp "automatically detects and redacts secrets
before they can enter threads or be transmitted to external services", replacing them with markers
like `[REDACTED:amp]`, covering "AWS, Google Cloud, and Azure credentials" plus dev platforms, LLM
APIs, Stripe, Slack. Documented limits: "may miss non-standard formats, encoded secrets, or custom
internal systems." Remediation is editing preceding messages or marking threads private. Amp still
advises "keeping secrets out of files the agent can read".

Data: Enterprise plan has "Minimal Data Retention"; providers may retain safety/abuse data up to
30 days; on Enterprise workspaces training "can *never* be enabled"; other tiers require workspace
admin approval for training. Linked personal ChatGPT/Grok subscriptions fall under those
providers' controls, which Amp cannot override. Sandboxing for Amp "orbs" uses e2b ephemeral
compute.

**[UNVERIFIED: exact settings-file path for `amp.permissions` (it is a VS Code settings key; the
CLI equivalent path was not confirmed), and whether a repo-committed file can set it.]** Absent
that, assume Amp permissions are **user-level, not repo-committable** — i.e. a repo scanner cannot
verify Amp hardening.

**Detection checklist — Amp:**
- [ ] `AGENTS.md` present (Amp's instruction file).
- [ ] Report as not-repo-verifiable: `amp.permissions` contains `reject`/`ask` rules for
      credential-reading `Bash` commands; `amp.mcpPermissions` restricts MCP servers; secret
      redaction relied on only as defence-in-depth.
- [ ] Confirm no `amp.dangerouslyAllowAll`-style setting is enabled. **[UNVERIFIED that such a
      key exists — I saw it referenced only in third-party writeups, not vendor docs.]**

### D.5 Kiro

Docs: <https://kiro.dev/docs/permissions/>, <https://kiro.dev/docs/kiroignore/>

**Permissions are YAML, deny-precedence.** Locations:
- User: `~/.kiro/settings/permissions.yaml`
- Workspace: `~/.kiro/workspace-roots/<hash>/permissions.yaml` — **note this is stored per-user
  outside the repository**, so Kiro permissions are **not repo-committable**.

Schema:

```yaml
rules:
  - capability: [capability_name]
    match: [glob_patterns]
    exclude: [glob_patterns]   # optional
    effect: [deny|ask|allow]
```

Capabilities: `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, `mcp`, `subagent`,
`skill`, `power`, `context`, `diagnostics`, `sandbox_network`. Meta: `all`, `builtin`,
`filesystem`. Precedence: "**deny > ask > allow — a deny rule always wins regardless of scope**."

Vendor examples:

```yaml
- capability: fs_write
  match: ["*.env", "*.pem", "*.key"]
  effect: deny

- capability: shell
  match: ["rm -rf *", "sudo *"]
  effect: deny
```

For secret *reading* you'd use `capability: fs_read` with the same match list plus
`~/.ssh/**`, `~/.aws/**`.

Hardcoded invariants — agent can never write `~/.kiro/settings/`, `.kiro/settings/`,
`~/.kiro/workspace-roots/`; always prompts for writes to `.git/**`, `.kiro/agents/**`,
`.kiro/hooks/**`, `.kiroignore`.

Autonomy modes (IDE, setting key `kiroAgent.agentAutonomy`): **Autopilot** (proceeds with allowed
operations without prompting) and **Supervised** (prompts before any action). Capability
permissions apply *after* the autonomy mode decides whether to proceed.

`.kiroignore` — gitignore syntax, repo-committable, "prevents Kiro from reading specific files".
Coverage is uneven: **IDE** = full enforcement across agent tools; **CLI V3** = *filtering search
results only* (content-search and filename-search); **Web** = "not available yet"; **Mobile** = no
support. Cannot re-include a file under an excluded parent directory. The IDE setting
`kiroAgent.agentIgnoreFiles` takes an array of ignore filenames (e.g.
`[".gitignore", ".kiroignore"]`) and **can be set to `[]` to disable ignoring entirely**.
The docs do not state whether `.kiroignore` blocks shell execution. **[UNVERIFIED: shell coverage
of `.kiroignore`. Assume not covered; use a `capability: shell` deny rule.]**

**Detection checklist — Kiro:**
- [ ] `.kiroignore` present at repo root covering `.env*`, `*.pem`, `*.key`, `id_rsa*`,
      `secrets/`. Annotate: **CLI V3 only filters search results**; IDE-only full enforcement.
- [ ] `.kiro/settings/` — reviewed (agent cannot write it, but a human can commit a weak one).
- [ ] `.kiro/agents/**`, `.kiro/hooks/**` — repo-committable and executable-ish; review.
- [ ] Report as not-repo-verifiable (stored in `~/.kiro/workspace-roots/<hash>/permissions.yaml`):
      `fs_read` deny rules for credential paths, `shell` deny rules, `web_fetch` set to `ask`,
      `mcp` restricted, autonomy mode = Supervised not Autopilot.
- [ ] Flag `kiroAgent.agentIgnoreFiles: []` in any committed VS Code/workspace settings — that
      disables ignore files entirely.

---

## Appendix: comparative summary

| Capability | OpenCode | Gemini CLI | Cursor | Copilot CLI | Aider | Cline | Roo | Amp | Kiro |
|---|---|---|---|---|---|---|---|---|---|
| Repo-committable permission policy | ✅ `opencode.json` | ❌ workspace policies **inert** (#18186); `.gemini/settings.json` partial | ✅ `.cursor/cli.json`, `.cursor/permissions.json`, `.cursor/sandbox.json` | ✅ `.github/copilot/settings.json` | ⚠️ `.aider.conf.yml` (no perms) | ❌ | ❌ | ❌ (user settings) | ❌ (per-user workspace-roots) |
| Deny rule for reading secret paths | ✅ `permission.read` | ✅ policy `deny` (user/admin tier only) | ✅ `Read(...)` in CLI perms | ⚠️ via `--deny-tool` / saved approvals | ❌ | ❌ | ⚠️ `.rooignore` | ✅ `reject` rule | ✅ `fs_read` deny |
| Deny precedence semantics | ❌ **last match wins** | ✅ highest priority wins | ✅ deny > allow (CLI) | ✅ deny always wins | n/a | n/a | n/a | ✅ | ✅ deny > ask > allow |
| Ignore file gates the shell | ❌ (no ignore file) | ❌ (search scope) | ❌ **explicitly documented** | n/a | ❌ | ❌ **explicitly documented** | ⚠️ partial, predefined cmd list | n/a | ❓ undocumented |
| OS-level sandbox | ❌ | ✅ seatbelt/docker/podman | ✅ `sandbox.json` (but `~/.ssh` readable) | ✅ MXC (Seatbelt/Bubblewrap/ProcessContainer) | ❌ | ❌ | ❌ | ✅ e2b (orbs) | ⚠️ `sandbox_network` capability |
| Network egress allowlist | ⚠️ `webfetch` perm only | ✅ `sandboxNetworkAccess` (default false) | ✅ `networkPolicy` + SSRF blocks | ✅ `allowedUrls`/`deniedUrls` + sandbox | ❌ | ❌ | ❌ | ❓ | ⚠️ `web_fetch` capability |
| Env-var redaction | ❌ | ✅ off by default | ⚠️ cloud Runtime Secrets only | ❓ | ❌ | ❌ | ❌ | ✅ secret redaction | ❌ |
| MCP allow/deny | ⚠️ `enabled: false` only | ✅ `mcp.allowed/excluded` + admin allowlist | ✅ `mcpAllowlist` / `Mcp(...)` | ✅ `--deny-tool 'Server(tool)'` | n/a | ⚠️ toggle | ⚠️ toggle | ✅ `amp.mcpPermissions` | ✅ `mcp` capability |
| Kill switch for YOLO | ❌ | ✅ `security.disableYoloMode` + admin Strict Mode | ❌ (mode is a UI choice) | ✅ `permissions.disableBypassPermissionsMode` | ❌ | ❌ | ❌ | ❓ | ⚠️ autonomy mode setting |

Legend: ✅ documented and enforceable · ⚠️ partial / weak · ❌ absent · ❓ not documented / unverified

### The three highest-value findings for a scanner

1. **OpenCode ships fully open** (`"*": "allow"`, bash allowed, `.env` only `ask`, and only for the
   `read` tool). Absence of a `permission` block in `opencode.json` is a hard fail, not a neutral.
2. **Gemini CLI's repo-level policy tier is broken** (issue #18186). A repo full of
   `.gemini/policies/*.toml` scores as hardened to a naive scanner and enforces nothing. Check the
   tier explicitly.
3. **Cursor's sandbox leaves `~/.ssh` and SSL certs readable**, and `.cursorignore` does not cover
   the terminal. The combination means SSH key theft is blocked by neither of Cursor's two
   headline controls — only by an explicit `Read(~/.ssh/**)` deny in `.cursor/cli.json`.
