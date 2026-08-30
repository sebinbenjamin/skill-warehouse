# Gemini CLI: hardening reference
Verified against: `main` docs at 2026-08-30; nightly `v0.59.0-nightly.20260830`.

## Config surfaces

Settings precedence, lowest → highest. Note that **project settings override user settings**: a repo can loosen a developer's personal hardening; only the system layer and admin console controls sit above it.

| File | Scope | Committed to repo? | Precedence / trust notes |
|---|---|---|---|
| (hardcoded defaults) | - | no | Layer 1. |
| `/etc/gemini-cli/system-defaults.json` · `C:\ProgramData\gemini-cli\system-defaults.json` · `/Library/Application Support/GeminiCli/system-defaults.json` | machine | no | Layer 2, system **defaults** (overridable). |
| `~/.gemini/settings.json` | user | no | Layer 3. |
| `.gemini/settings.json` | repo | **yes** | Layer 4: **overrides user settings**. Can register hooks, MCP servers, and loosen sandbox/YOLO keys. |
| `/etc/gemini-cli/settings.json` · `C:\ProgramData\gemini-cli\settings.json` · `/Library/Application Support/GeminiCli/settings.json` | machine | no | Layer 5, system **overrides**: wins over everything else. Still modifiable by privileged local users. |
| environment variables (incl. from `.env` files) | shell | - | Layer 6. |
| CLI arguments | invocation | - | Layer 7, highest. |
| `.gemini/policies/*.toml` | repo | yes | Policy **Workspace** tier: **currently non-functional (issue #18186)**. Expresses intent, enforces nothing. |
| `~/.gemini/policies/*.toml` | user | no | Policy **User** tier: the lowest tier that actually works. |
| `/etc/gemini-cli/policies` · `/Library/Application Support/GeminiCli/policies` · `C:\ProgramData\gemini-cli\policies` | machine | no | Policy **Admin** tier. |
| `.gemini/sandbox.Dockerfile`, `.gemini/sandbox-macos-custom.sb` | repo | yes | Executable configuration: a repo-supplied profile can be weaker than the built-in. Scan targets. |
| `.geminiignore` | repo | yes | Search-scope filtering only. |
| `~/.gemini/trustedFolders.json` | user | no | Folder Trust store; managed via `/permissions`. |
| Enterprise admin console (<https://goo.gle/manage-gemini-cli>) | org | no | "Enforced globally and cannot be overridden by users locally": immutable at the local level, unlike system settings files. |

Editor schema: `https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json`.

Policy tier base priorities: Default 1, Extension 2, **Workspace 3 (inert)**, User 4, Admin 5. Final priority = `tier_base + (toml_priority / 1000)`, `toml_priority` 0–999, highest wins.

## What each control actually stops

| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| Policy rule `decision = "deny"` (no `argsPattern`) | T4 harness deny rule | The tool entirely: denied tools are "completely excluded from the model's memory" | Anything if written in the Workspace tier (inert); MCP wildcards when a server name contains `_` |
| Policy rule with `argsPattern` / `commandRegex` | T4 harness deny rule | Matched invocations of the tool | Re-encoded or aliased commands; the tool still exists in model memory |
| `tools.confirmationRequired` | T4 harness deny rule | Silent execution: "takes precedence over allowed tools and core tool allowlists" | Execution after the human approves |
| `tools.core` (allowlist) | T4 harness deny rule | Built-in tools outside the list | MCP tools |
| `tools.exclude` | T4 harness deny rule | Discovery of the named tools. **Deprecated** in favour of policy `deny`; weaker guarantees | - |
| `tools.allowed` | - (loosening) | Nothing; it *bypasses* confirmation dialogs, e.g. `run_shell_command(git)` | Flag broad entries as findings |
| `tools.sandbox` (docker/podman/sandbox-exec) + `SEATBELT_PROFILE` | T1 OS sandbox | Writes outside the project directory; with `restrictive-closed`, network too | Reads inside the profile's readable set; default `permissive-open` **allows network** |
| `security.toolSandboxing` | T1 OS sandbox | Isolates individual tools rather than the whole CLI process (default `false`) | Not a substitute for a deny rule |
| `tools.sandboxNetworkAccess` (default `false`) | T2 egress allowlist | All network from inside the sandbox when false | Network when the sandbox is off entirely (the default) |
| `security.environmentVariableRedaction.enabled` (default `false`) | T3 credential scrub | Env vars judged to "may contain secrets" reaching the model | Secrets read out of files; unknown coverage. **[UNVERIFIED: exact redaction heuristic and what it covers beyond env vars.]** |
| Folder Trust (`security.folderTrust.enabled`, default `true`) | T4 harness deny rule | In an untrusted folder: loading `.gemini/settings.json`, loading project `.env`, extension install/update/removal, unprompted tool runs, auto-loading memory files | Bypassed by `GEMINI_CLI_TRUST_WORKSPACE=true` |
| `security.disableYoloMode`, `security.disableAlwaysAllow` | T4 harness deny rule | `--yolo` / `--approval-mode yolo`; the "Always allow" button | Nothing else |
| Hooks (`hooks.BeforeTool` returning `{"decision": "deny"}`, or exit 2) | T5 hook | Whatever the hook script decides: the place to put a custom secret scanner | Nothing by default; hooks are also the primary repo-side RCE surface |
| `.geminiignore`, `context.fileFiltering.respectGitIgnore` | T6 ignore file | Matched paths appearing **when searching** and in `@`-mentions | `run_shell_command`: nothing in the primary docs claims otherwise. Assume it does not. |
| `GEMINI.md` / memory files | T7 instruction file | Nothing; steering only | Any tool call |
| Admin console MCP allowlist | T4 harness deny rule | Non-allowlisted servers are ignored; local `command`, `args`, `env`, `cwd`, `httpUrl`, `tcp` are **automatically cleared**: kills the MCP-`env`-as-exfil-channel pattern | Nothing configured outside MCP |

## Rule semantics you must get right

1. **The Workspace policy tier is non-functional.** Verbatim: policies in a workspace's `.gemini/policies` directory "will not have any effect" (issue #18186). A repo full of `.toml` deny rules scores as hardened to a naive scanner and enforces nothing. Policy hardening must go in `~/.gemini/policies/` or the admin dir.
2. **Project `.gemini/settings.json` overrides user `settings.json`.** A hostile or careless repo can turn off the sandbox, enable network, register hooks, and add trusted MCP servers.
3. **Repo-registered hooks are arbitrary code execution in the agent loop.** Events: `BeforeTool`, `AfterTool`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `AfterModel`, `BeforeToolSelection`, `SessionStart`, `SessionEnd`, `PreCompress`, `Notification`. `hooksConfig.enabled` is the canonical kill switch ("When disabled, no hooks will be executed"); `hooksConfig.disabled` takes an array.
4. **MCP server names must not contain `_`.** Verbatim: "Do not use underscores (`_`) in your MCP server names… the parser will misinterpret the server identity, which can cause wildcard rules and security policies to **fail silently**." `mcp_my_server_tool` breaks `mcp_*` rules.
5. **`commandRegex` is matched against the JSON representation** `{"command":"..."}`. "Anchors like `^` or `$` apply to the full JSON string, so `^` should usually be avoided here."
6. Redirection (`>`, `>>`, `<`, `<<`, `<<<`) forces confirmation even on matched rules unless `allowRedirection = true`. Useful anti-exfil default; `allowRedirection = true` is a finding.
7. Rule fields: `toolName` (string or array; wildcards `*`, `mcp_server_*`, `mcp_*_toolName`, `mcp_*`), `subagent`, `mcpName`, `toolAnnotations`, `argsPattern` (regex over stable-JSON args), `commandPrefix`, `commandRegex`, `decision` (`allow`|`deny`|`ask_user`), `priority`, `denyMessage`, `modes`, `interactive`, `allowRedirection`.
8. **Admin policies in the standard system dir are ignored unless** the dir is root-owned and not group/world-writable (Linux/macOS) or lives in `C:\ProgramData` without standard-user write (Windows). Supplemental policies via `--admin-policy` / `adminPolicyPaths` skip those checks **and are ignored entirely if standard-location policies exist**.
9. Approval modes: `default`, `autoEdit`, `plan` (strict read-only), `yolo`. Persisted "Allow for all future sessions" approvals cascade to *more permissive* modes only (`plan` < `default` < `autoEdit` < `yolo`).
10. `context.fileFiltering.customIgnoreFilePaths` (default `[]`): "These files take precedence over .geminiignore and .gitignore", earlier entries win. Check what it points at.
11. `mcpServers.<NAME>.trust: true`: "Trust this server and bypass all tool call confirmations". Always a finding. `excludeTools` takes precedence over `includeTools`.
12. `GEMINI_CLI_TRUST_WORKSPACE=true` "trusts the current workspace for the duration of the session, bypassing the folder trust check". `GEMINI_CLI_TRUSTED_FOLDERS_PATH` relocates the trust store.
13. **Auth tier decides whether your code trains a model.** Free personal Google account (individual Gemini Code Assist) → "Your prompts, answers, and related code are collected"; unpaid Gemini API key → yes. Standard/Enterprise Code Assist, paid API key, and Vertex AI GenAI API → no. `privacy.usageStatisticsEnabled` (**default `true`**) disables both telemetry and prompt/code collection on the individual/unpaid tiers, telemetry only on paid/enterprise.
14. Enterprise admin controls: **Strict Mode** default *enabled* ("users will not be able to enter yolo mode"), Extensions default disabled, MCP default disabled, MCP allowlist and Required MCP Servers in preview. "If the allowlist contains one or more servers, all locally configured servers not present in the allowlist are ignored."

## Detection checklist

**Repo-visible** (`.gemini/**`, `.geminiignore`, workflows):

| Check | Severity | Where to look |
|---|---|---|
| `--yolo` / `--approval-mode yolo` in scripts, Makefiles, CI, or repo docs, with no container | Critical | `.github/workflows/**`, `Makefile`, `package.json`, `README` |
| Any `hooks.*` entry registered by the repo (session-start RCE) | Critical | `.gemini/settings.json` → `hooks`, `hooksConfig` |
| `mcpServers.*.env` / `headers` with `$VAR` / `${VAR}` substitution pointing at a remote `url`/`httpUrl` | Critical | `.gemini/settings.json` → `mcpServers` |
| `mcpServers.*.trust: true` (bypasses all confirmations) | Critical | `.gemini/settings.json` |
| `security.disableYoloMode: false` or `security.folderTrust.enabled: false` set by the repo | High | `.gemini/settings.json` → `security` |
| `tools.sandbox: false` or `tools.sandboxNetworkAccess: true` set by the repo | High | `.gemini/settings.json` → `tools` |
| Broad `tools.allowed` entries, especially bare `run_shell_command` | High | `.gemini/settings.json` → `tools.allowed` |
| `.gemini/policies/*.toml` present → **looks hardened, enforces nothing** (#18186) | High | `.gemini/policies/` |
| `.gemini/sandbox.Dockerfile` / `.gemini/sandbox-macos-custom.sb` weaker than the built-in profile | High | read both files |
| MCP server name containing `_` (silently breaks `mcp_*` policy rules) | High | `.gemini/settings.json` → `mcpServers` keys |
| `context.fileFiltering.customIgnoreFilePaths` pointing at a permissive file | Medium | `.gemini/settings.json` → `context` |
| `privacy.usageStatisticsEnabled: true` where the org wants it off | Medium | `.gemini/settings.json` |
| `.geminiignore` missing or not covering `.env*`, `*.pem`, `*.key`, `id_rsa*`, `.netrc`, `.npmrc`, `secrets/` | Medium, search-scope only, note as weak | repo root |
| `allowRedirection = true` in any committed policy | Medium | `.gemini/policies/*.toml` |
| `tools.exclude` used instead of policy `deny` (deprecated, weaker) | Low | `.gemini/settings.json` |

**Must verify out-of-band** (user / machine / admin console; not repo-enforceable):

| Check | Severity | Where to look |
|---|---|---|
| Auth is a free personal Google account or unpaid API key → repo contents train the model | High | `/auth` in the CLI; account tier |
| No `~/.gemini/policies/*.toml` deny rules for credential reads and `env`/`printenv` shell | High | `~/.gemini/policies/` |
| `GEMINI_CLI_TRUST_WORKSPACE=true` in shell profiles or CI | High | `~/.bashrc`, `~/.zshrc`, `.github/workflows/**` |
| `security.environmentVariableRedaction.enabled` not `true` (off by default) | High | `~/.gemini/settings.json` |
| Sandbox unset (off by default) or left on the default `permissive-open` seatbelt profile, which allows network | High | `~/.gemini/settings.json`, `GEMINI_SANDBOX`, `SEATBELT_PROFILE` |
| `security.disableYoloMode` / `security.disableAlwaysAllow` not `true` | Medium | `~/.gemini/settings.json` |
| `security.folderTrust.enabled` not `true`; unexpected entries in `~/.gemini/trustedFolders.json` | Medium | user config |
| `mcp.allowed` empty (no server-level allowlist) | Medium | `~/.gemini/settings.json` |
| Enterprise console: Strict Mode on, Extensions/MCP defaults, MCP allowlist populated | Medium | <https://goo.gle/manage-gemini-cli> |
| `privacy.usageStatisticsEnabled: false` | Low | `~/.gemini/settings.json` |

## Hardened baseline

### Policy: must live in `~/.gemini/policies/` (workspace tier is inert)

Write this to **`~/.gemini/policies/secrets.toml`**. Committing the same content to `.gemini/policies/secrets.toml` has **no effect** (issue #18186); if the repo wants a record of intent, ship it as documentation and state plainly that it is not enforced.

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

### User settings: `~/.gemini/settings.json`

```json
{
  "security": {
    "environmentVariableRedaction": { "enabled": true },
    "disableYoloMode": true,
    "disableAlwaysAllow": true,
    "enablePermanentToolApproval": false,
    "autoAddToPolicyByDefault": false,
    "folderTrust": { "enabled": true }
  },
  "tools": {
    "sandbox": "docker",
    "sandboxNetworkAccess": false,
    "confirmationRequired": ["run_shell_command", "write_file", "replace", "web_fetch"]
  },
  "privacy": { "usageStatisticsEnabled": false },
  "hooksConfig": { "enabled": false }
}
```

### Repo settings: `.gemini/settings.json`

Only tightening keys belong here, because this layer *overrides* the user layer.

```json
{
  "context": {
    "fileFiltering": {
      "respectGitIgnore": true,
      "respectGeminiIgnore": true
    }
  },
  "tools": {
    "sandboxNetworkAccess": false,
    "confirmationRequired": ["run_shell_command", "write_file", "replace", "web_fetch"]
  },
  "security": { "folderTrust": { "enabled": true } },
  "hooksConfig": { "enabled": false }
}
```

**Ignored from repo scope:** `.gemini/policies/*.toml` (Workspace tier, inert). **Not settable from repo scope in any meaningful way:** admin console controls, and the auth/training tier. **Settable from repo scope but should not be, because it only loosens:** `tools.allowed`, `mcpServers.*.trust`, `hooks.*`, `security.disableYoloMode: false`.

`.geminiignore` (repo root) is worth committing as defence in depth, understood as search-scope only, one glob per line: `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `.netrc`, `.npmrc`, `secrets/`.

## Verify at runtime

- `/permissions` inside the CLI: shows Folder Trust state and lets you inspect trusted folders.
- Confirm the effective policy tier: list `~/.gemini/policies/`, the admin policy dir for the platform, and `.gemini/policies/`; anything found only in the last is inert.
- Confirm the sandbox is actually on: `echo $GEMINI_SANDBOX $SEATBELT_PROFILE`, or launch with `--sandbox` / `-s` and check the CLI's sandbox indicator. Inside a session, a shell command touching a path outside the project should fail.
- `env | grep -E 'GEMINI_CLI_TRUST_WORKSPACE|GEMINI_CLI_TRUSTED_FOLDERS_PATH|GEMINI_TELEMETRY_'`: any hit overrides file settings.
- Test the deny rules empirically: ask for `read_file` on `.env` and `run_shell_command` with `printenv`; both should be refused with the `denyMessage`, not merely prompted.
- Verify MCP server names contain no `_` before trusting any `mcp_*` wildcard rule.
- Enterprise controls are only visible at <https://goo.gle/manage-gemini-cli>; they cannot be confirmed from the machine.

## Sources

- <https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md>
- <https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md>
- <https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md>
- <https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/gemini-ignore.md>
- <https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md>
- <https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md>
- <https://github.com/google-gemini/gemini-cli/blob/main/docs/admin/enterprise-controls.md>
- <https://google-gemini.github.io/gemini-cli/docs/tos-privacy.html>
- <https://github.com/google-gemini/gemini-cli/issues/18186>
