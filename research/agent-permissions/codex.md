> **Caution (2026-08-30):** the three baseline `config.toml` / `requirements.toml` snippets in this file are invalid TOML as written — top-level keys (`default_permissions`, `cli_auth_credentials_store`, `allow_managed_hooks_only`) appear after table headers and bind to the wrong table. Corrected versions live in `agent-permissions/references/codex.md`; copy from there.

# Hardening OpenAI Codex CLI against secret / environment exfiltration

Research date: **2026-08-30**. Version context: docs reference Codex **0.138.0+** (permission profiles), **0.134.0+** (profile-file change), **0.115+** (Linux sandbox moved to `bwrap`).

> **Doc-location warning (easy to get wrong):** the old primary sources have moved.
> `github.com/openai/codex/docs/*.md` are now one-line stubs that link out. `developers.openai.com/codex/*`
> 308-redirects to `learn.chatgpt.com/docs/*`. Every doc page has a machine-readable Markdown twin at
> `<url>.md`, and the index is <https://learn.chatgpt.com/llms.txt>. All citations below use the
> canonical `learn.chatgpt.com` URLs.

---

## Summary

**What Codex CLI gives you today**

- Two independent layers: **sandbox** (what is technically possible) and **approval policy** (when it stops and asks). <https://learn.chatgpt.com/docs/agent-approvals-security>
- The **legacy** knobs (`sandbox_mode` + `[sandbox_workspace_write]`) restrict **writes and network only**. Under both `read-only` and `workspace-write`, **the entire filesystem is readable** — `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials`, `cat ../other-repo/.env` all succeed with no approval prompt. Verified in source, not just docs (see §3/§5).
- The **new** knobs — **permission profiles** (`default_permissions` + `[permissions.<name>]`, beta) — are the *only* local mechanism that can deny **reads**. They support `":root" = "deny"`, `":minimal" = "read"`, and glob deny rules like `"**/*.env" = "deny"`. <https://learn.chatgpt.com/docs/permissions>
- **You cannot use both systems at once.** If `sandbox_mode` appears in *any* loaded config layer (or `--sandbox` is passed), Codex ignores `default_permissions` entirely. This is the single biggest hardening foot-gun.
- **Env vars containing `KEY`, `SECRET`, or `TOKEN` are forwarded to spawned commands by default.** `shell_environment_policy.ignore_default_excludes` defaults to `true`, which *skips* the automatic secret-name filter. You must explicitly set it to `false`.
- There is **no `.codexignore`** and no file-read exclusion outside permission profiles / managed `deny_read` (verified: zero hits for `codexignore` in `openai/codex`).
- `disable_response_storage` **no longer exists** in the Codex codebase (zero hits, absent from the config reference). ZDR is an API-org-level control, not a CLI flag.

**Minimum viable hardening** (full snippet in §9)

1. Use permission profiles, not `sandbox_mode`. Deny `:root` reads, allow `:minimal` + workspace.
2. Deny-glob `.env`/`*.pem`/key material; deny `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.codex`.
3. `shell_environment_policy.inherit = "core"` + `ignore_default_excludes = false` + exclude filters.
4. `approval_policy = "on-request"` (or `"untrusted"`); never `"never"`, never `--yolo`.
5. Network off, or `features.network_proxy = true` with a tight domain allowlist (the proxy is what actually enforces the allowlist).
6. `history.persistence = "none"`; keep `otel.log_user_prompt = false`; `cli_auth_credentials_store = "keyring"`.
7. Do **not** trust unreviewed projects — a committed `.codex/config.toml` outranks your user config.

---

## 1. Config file locations, precedence, and what may be committed

Sources: <https://learn.chatgpt.com/docs/config-file/config-basic>, <https://learn.chatgpt.com/docs/config-file/config-advanced>

### Precedence (highest first), verbatim

> 1. CLI flags and `--config` overrides
> 2. Project config files: `.codex/config.toml`, ordered from the project root down to your current working directory (closest wins; trusted projects only)
> 3. Profile files selected with `--profile profile-name` (`~/.codex/profile-name.config.toml`)
> 4. User config: `~/.codex/config.toml`
> 5. System config (if present): `/etc/codex/config.toml` on Unix
> 6. Built-in defaults

Above all of that sit the enterprise layers (§6/§7):

- **Managed defaults**: `/etc/codex/managed_config.toml` (Unix) or `~/.codex/managed_config.toml` (Windows/non-Unix), plus macOS MDM `com.openai.codex:config_toml_base64`. Verbatim: "At startup, they override the user's local `config.toml` and any CLI `--config` overrides."
- **Admin requirements**: `/etc/codex/requirements.toml` (Unix, incl. macOS) or `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows), then cloud-managed bundle, then legacy `managed_config.toml` reinterpretation, then MDM `requirements_toml_base64`. Requirements *constrain* legal values; conflicting values fall back to a compatible one and the user is notified.
  <https://learn.chatgpt.com/docs/enterprise/managed-configuration>

### Locations

| Path | Role | Committable? |
| --- | --- | --- |
| `~/.codex/config.toml` (`$CODEX_HOME/config.toml`) | User config. `CODEX_HOME` defaults to `~/.codex`. | No (machine-local: provider/auth/telemetry) |
| `~/.codex/profile-name.config.toml` | Named profile layer, selected with `--profile profile-name` | No |
| `<repo>/.codex/config.toml` | Project config, loaded root→cwd, closest wins, **trusted projects only** | **Yes** — the key scanner target |
| `<repo>/.codex/hooks.json`, `~/.codex/hooks.json` | Lifecycle hooks | Yes (project) |
| `<repo>/.codex/rules/*.rules`, `~/.codex/rules/default.rules` | Execpolicy command rules (Starlark) | Yes (project) |
| `~/.codex/AGENTS.md`, `~/.codex/AGENTS.override.md` | Global agent instructions | No |
| `<dir>/AGENTS.md`, `<dir>/AGENTS.override.md` | Project/dir agent instructions | Yes |
| `/etc/codex/config.toml` | System config | n/a |
| `~/.codex/auth.json` | Credentials when `cli_auth_credentials_store = "file"` | **Never** |
| `~/.codex/history.jsonl` | Session transcripts | **Never** |

### Keys a project-local `.codex/config.toml` may NOT set

Verbatim (<https://learn.chatgpt.com/docs/config-file/config-advanced#project-config-files-codexconfigtoml>):

> Codex ignores the following keys in project-local `.codex/config.toml` and prints a startup warning when it sees them: `openai_base_url`, `chatgpt_base_url`, `apps_mcp_product_sku`, `model_provider`, `model_providers`, `notify`, `profile`, `profiles`, `experimental_realtime_ws_base_url`, and `otel`.

**Security note:** that list does *not* include `approval_policy`, `sandbox_mode`, `sandbox_workspace_write`, `default_permissions`, `[permissions]`, `[mcp_servers]`, `[features]`, or `[hooks]`. A committed `.codex/config.toml` **can** downgrade your sandbox and approvals, add MCP servers, and add hooks — it just needs the project to be trusted. Hooks additionally require per-hash trust review via `/hooks` unless managed or `--dangerously-bypass-hook-trust` is passed.

### Trust

```toml
# ~/.codex/config.toml
[projects."/absolute/path/to/project"]
trust_level = "trusted"   # or "untrusted"
```

(<https://learn.chatgpt.com/docs/config-file/config-sample>, <https://learn.chatgpt.com/docs/config-file/config-reference>)

> Untrusted projects skip project-scoped `.codex/` layers, including project-local config, hooks, and rules.

Project root discovery (controls where `.codex/` and `AGENTS.md` search starts):

```toml
project_root_markers = [".git", ".hg", ".sl"]   # [] = never walk up
```

### Profiles

Profiles are **separate files**, not `[profiles.x]` tables, since 0.134.0:

```toml
# ~/.codex/deep-review.config.toml
model = "gpt-5.5"
model_reasoning_effort = "xhigh"
approval_policy = "on-request"
```

```shell
codex --profile deep-review
codex exec --profile deep-review "review this change"
```

> In Codex 0.134.0 and later, `--profile` no longer reads `[profiles.profile-name]` from `config.toml`, and the top-level `profile = "profile-name"` selector is no longer supported.

### AGENTS.md

<https://learn.chatgpt.com/docs/agent-configuration/agents-md>

Discovery: `$CODEX_HOME/AGENTS.override.md` else `$CODEX_HOME/AGENTS.md` → then project root down to cwd, checking `AGENTS.override.md`, then `AGENTS.md`, then `project_doc_fallback_filenames`; at most one file per directory; concatenated root-first so the closest file wins.

`project_doc_max_bytes` defaults to **32 KiB**; Codex "stops adding files once the combined size reaches the limit". This caps instruction-injection surface — it is **not** a read-exclusion mechanism.

---

## 2. `approval_policy`, `sandbox_mode`, and the dangerous flags

Sources: <https://learn.chatgpt.com/docs/agent-approvals-security>, <https://learn.chatgpt.com/docs/sandboxing>, <https://learn.chatgpt.com/docs/config-file/config-reference>

### `approval_policy`

Config-reference type string, verbatim:

```
untrusted | on-request | never | { granular = { sandbox_approval = bool, rules = bool, mcp_elicitations = bool, request_permissions = bool, skill_approval = bool } }
```

> Controls when Codex pauses for approval before executing commands. … **`on-failure` is deprecated**; use `on-request` for interactive runs or `never` for non-interactive runs.

| Value | Behavior |
| --- | --- |
| `untrusted` | "The agent asks before running commands that aren't in its trusted set." Verbatim: "Codex runs only known-safe read operations automatically. Commands that can mutate state or trigger external execution paths (for example, destructive Git operations or Git output/config-override flags) require approval." |
| `on-request` | "The agent works inside the sandbox by default and asks when it needs to go beyond that boundary." Default in the `Auto` preset. |
| `never` | "The agent doesn't stop for approval prompts." Works with any sandbox mode. |
| `on-failure` | **Deprecated.** Still parsed; do not use. |
| `{ granular = {…} }` | Per-category: `true` lets that prompt category surface interactively; `false` **auto-rejects** it (fail-closed). Categories: sandbox escalations, execpolicy `prompt` rules, MCP elicitations, `request_permissions` tool prompts, skill-script approvals. |

Related: `approvals_reviewer = "user"` (default) or `"auto_review"` — a reviewer subagent decides eligible approvals instead of a human. Auto-review "doesn't change the sandbox boundary" and only sees actions that *already* require approval; prompt-build/review/parse failures fail closed; timeouts do not run the action. Default reviewer policy: <https://github.com/openai/codex/blob/main/codex-rs/core/src/guardian/policy.md>. See <https://learn.chatgpt.com/docs/sandboxing/auto-review>.

Also useful: `allow_login_shell = false` — "optional hardening: disallow login shells for shell-based tools" (defaults `true`; with `false`, `login = true` requests are rejected and omitted `login` defaults to non-login shells, so `~/.zprofile` etc. are not sourced).

### `sandbox_mode`

Type: `read-only | workspace-write | danger-full-access`.

| Value | Reads | Writes | Network |
| --- | --- | --- | --- |
| `read-only` | **Entire filesystem** (see §3/§5) | none; commands need approval | off |
| `workspace-write` | **Entire filesystem** | workspace roots + `$TMPDIR` + `/tmp` + `writable_roots`, minus protected `.git`/`.agents`/`.codex` | off unless `network_access = true` |
| `danger-full-access` | everything | everything | on |

Launch defaults, verbatim:

> - Version-controlled folders: `Auto` (workspace write + on-request approvals)
> - Non-version-controlled folders: `read-only`
> - … Codex may also start in `read-only` until you explicitly trust the working directory (for example, via an onboarding prompt or `/permissions`).
> - The workspace includes the current directory and temporary directories like `/tmp`. Use the `/status` command to see which directories are in the workspace.

### Flags

| Flag | Meaning |
| --- | --- |
| `--sandbox, -s <read-only\|workspace-write\|danger-full-access>` | Select sandbox policy |
| `--ask-for-approval, -a <untrusted\|on-request\|never>` | Select approval policy |
| `--add-dir <path>` | "Grant additional directories **write** access alongside the main workspace." Repeatable. |
| `--full-auto` | **Deprecated.** `codex exec --full-auto` is "a deprecated compatibility path and prints a warning." Prefer `--sandbox workspace-write`. No longer in the global-flag table. |
| `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`) | "Run every command without approvals or sandboxing. Only use inside an externally hardened environment." Also flips `web_search` default to `live`. |
| `--dangerously-bypass-hook-trust` | Run enabled hooks without persisted hook trust |
| `--ignore-user-config` | "Do not load `$CODEX_HOME/config.toml`." (auth still uses `CODEX_HOME`) — **bypasses hardened user config** |
| `--ignore-rules` | "Do not load user or project execpolicy `.rules` files for this run." |
| `--strict-config` | Error when `config.toml` contains unrecognized fields — catches typo'd hardening keys |
| `--search` | Sets `web_search = "live"` |
| `--enable <feature>` / `--disable <feature>` | Force feature flags on/off |

### Canonical combinations (verbatim table, condensed)

| Intent | Flags |
| --- | --- |
| Auto (preset) | *no flags* or `--sandbox workspace-write --ask-for-approval on-request` |
| Safe read-only browsing | `--sandbox read-only --ask-for-approval on-request` |
| Read-only non-interactive (CI) | `--sandbox read-only --ask-for-approval never` |
| Edit automatically, approve untrusted commands | `--sandbox workspace-write --ask-for-approval untrusted` |
| Auto-review mode | `--sandbox workspace-write --ask-for-approval on-request -c approvals_reviewer=auto_review` |
| Dangerous full access | `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`) |

### `config.toml` form, verbatim from the docs

```toml
# Always ask for approval mode
approval_policy = "untrusted"
sandbox_mode    = "read-only"
allow_login_shell = false # optional hardening: disallow login shells for shell-based tools

# Optional: Allow network in workspace-write mode
[sandbox_workspace_write]
network_access = true

# Optional: granular approval policy
# approval_policy = { granular = {
#   sandbox_approval = true,
#   rules = true,
#   mcp_elicitations = true,
#   request_permissions = false,
#   skill_approval = false
# } }
```

---

## 3. Sandbox internals

### `[sandbox_workspace_write]`

Sources: <https://learn.chatgpt.com/docs/config-file/config-reference>, <https://learn.chatgpt.com/docs/config-file/config-advanced#approval-policies-and-sandbox-modes>

Verbatim from Advanced Config:

```toml
[sandbox_workspace_write]
exclude_tmpdir_env_var = false  # Allow $TMPDIR
exclude_slash_tmp = false       # Allow /tmp
writable_roots = ["/Users/YOU/.pyenv/shims"]
network_access = false          # Opt in to outbound network
```

- `writable_roots: array<string>` — "Additional writable roots when `sandbox_mode = \"workspace-write\"`." Write-only extension; does not affect reads (reads are already global).
- `network_access: boolean` — default `false`.
- `exclude_tmpdir_env_var: boolean` — "Exclude `$TMPDIR` from writable roots in workspace-write mode."
- `exclude_slash_tmp: boolean` — "Exclude `/tmp` from writable roots in workspace-write mode."

### OS mechanisms (verbatim)

> - **macOS** uses Seatbelt policies and runs commands using `sandbox-exec` with a profile (`-p`) that corresponds to the `--sandbox` mode you selected. When restricted read access enables platform defaults, Codex appends a curated macOS platform policy (instead of broadly allowing `/System`) to preserve common tool compatibility.
> - **Linux** uses `bwrap` plus `seccomp` by default.
> - **Windows** uses the Linux sandbox implementation when running in Windows Subsystem for Linux 2 (WSL2). WSL1 was supported through Codex `0.114`; starting in `0.115`, the Linux sandbox moved to `bwrap`, so WSL1 is no longer supported. When running natively on Windows, Codex uses a Windows sandbox implementation.

Enforcement nuances (<https://learn.chatgpt.com/docs/permissions#how-enforcement-works>):

> - On macOS, Codex uses Seatbelt sandbox profiles. If the selected policy cannot be enforced by the platform sandbox, Codex refuses to run the command instead of silently running it unsandboxed.
> - On Linux and WSL, Codex uses bubblewrap and seccomp, **with Landlock available for compatibility fallback paths.** The strongest enforcement path depends on user namespaces and kernel support; restricted container hosts can force compatibility paths, and unsupported split policies are refused.
> - On native Windows, `elevated` sandboxing is strongest because it can use dedicated lower-privilege sandbox users, filesystem permission boundaries, and firewall rules. `unelevated` sandboxing is a fallback with **weaker network isolation and cannot enforce every split read/write carveout**, so unsupported policies are refused. Use WSL when you need the Linux sandbox model.

Linux/WSL prerequisite: `sudo apt install bubblewrap` (or `dnf`). Codex uses the first `bwrap` on `PATH`, otherwise a bundled helper needing unprivileged user namespaces. Ubuntu 24.04 may need the `bwrap-userns-restrict` AppArmor profile loaded.

Windows native:

```toml
[windows]
sandbox = "elevated"              # Recommended; "unelevated" is the weaker fallback
# sandbox_private_desktop = true  # default; set false only for compatibility
```

IDE extension on Windows — keep the agent inside WSL2 so it inherits Linux sandbox semantics:

```json
{ "chatgpt.runCodexInWindowsSubsystemForLinux": true }
```

### Does the sandbox restrict reads?

**Legacy `sandbox_mode`: no.** The docs are vague; the source is unambiguous.

`codex-rs/protocol/src/permissions.rs`, `impl From<&SandboxPolicy> for FileSystemSandboxPolicy`:

- `SandboxPolicy::ReadOnly` → a single entry: `FileSystemSpecialPath::Root` with `FileSystemAccessMode::Read`.
- `SandboxPolicy::WorkspaceWrite` → `Root = Read`, plus `project_roots = Write`, plus `/tmp` and `$TMPDIR` writes (unless excluded), plus `writable_roots`; then `.git`, `.agents`, `.codex` appended as read-only carve-outs.

`has_full_disk_read_access()` therefore returns `true`, and `codex-rs/sandboxing/src/seatbelt.rs` emits literally:

```
; allow read-only file operations
(allow file-read*)
```

(The Seatbelt base policy starts `(deny default)` and grants no blanket `file-read*` of its own — the grant comes from this branch.)

**Conclusion: with `sandbox_mode = "read-only"` or `"workspace-write"`, the agent can read any file the user can read** — `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.config/gcloud`, sibling repos' `.env`, `~/.codex/auth.json` — with no approval prompt. Only **permission profiles** (§5) or admin `deny_read` change that.

Sources: <https://github.com/openai/codex/blob/main/codex-rs/protocol/src/permissions.rs>, <https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt.rs>, <https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt_base_policy.sbpl>

### Protected paths in writable roots (verbatim)

> In the default `workspace-write` sandbox policy, writable roots still include protected paths:
> - `<writable_root>/.git` is protected as read-only whether it appears as a directory or file.
> - If `<writable_root>/.git` is a pointer file (`gitdir: ...`), the resolved Git directory path is also protected as read-only.
> - `<writable_root>/.agents` is protected as read-only when it exists as a directory.
> - `<writable_root>/.codex` is protected as read-only when it exists as a directory.
> - Protection is recursive, so everything under those paths is read-only.

So `.git` is protected against **writes**, not reads. Extending `:workspace` in a permission profile "keeps the workspace root's `.codex` directory read-only unless you explicitly override it."

### Network

Default off in `workspace-write`. Enabling network is only half the story:

```toml
[sandbox_workspace_write]
network_access = true

[features.network_proxy]
enabled = true
domains = { "api.openai.com" = "allow", "example.com" = "deny" }
```

Verbatim truth table:

> - Network off + `network_proxy` on: network stays off, and the feature does nothing.
> - Network on + `network_proxy` off: network stays on with **unrestricted direct outbound access**.
> - Network on + `network_proxy` on: network stays on, and outbound traffic is constrained by the configured network policy.

Policy semantics (verbatim, condensed): allowlist-first; exact hosts match only themselves; `*.example.com` matches subdomains but not the apex; `**.example.com` matches apex plus subdomains; a global `*` allow rule matches any non-denied public host; `deny` always wins; `*` is allow-only. `allow_local_binding = false` (default) blocks loopback/link-local/private destinations, and "hostnames that resolve to local/private IPs stay blocked even if they match the allowlist."

Proxy defaults (verbatim values): `enabled=false`, `domains` unset (nothing allowed), `unix_sockets` unset, `allow_local_binding=false`, `enable_socks5=true`, `enable_socks5_udp=true`, `allow_upstream_proxy=true`, `dangerously_allow_non_loopback_proxy=false`, `dangerously_allow_all_unix_sockets=false`. Default listeners `http://127.0.0.1:3128` and `http://127.0.0.1:8081`.

DNS rebinding: "Lookups that fail or time out are blocked. Hostnames that resolve to non-public addresses are blocked. The check reduces DNS rebinding risk, but it does not eliminate it. … If hostile DNS is in scope, enforce egress controls at a lower layer too."

**The proxy does not filter:** web search, app/connector tool calls, MCP server connections, browser/Computer Use, Codex cloud tasks, or the client's own model/auth requests.

### Testing the sandbox

```bash
codex sandbox macos   [--permissions-profile <name>] [--log-denials] [COMMAND]...
codex sandbox linux   [--permissions-profile <name>] [COMMAND]...
codex sandbox windows [--permissions-profile <name>] [COMMAND]...
```

Aliases: `codex debug`, `codex sandbox seatbelt`, `codex sandbox landlock`.

---

## 4. Environment variable policy — keeping `*_KEY` / `*_TOKEN` out of the shell

Sources: <https://learn.chatgpt.com/docs/config-file/config-advanced#shell-environment-policy>, <https://learn.chatgpt.com/docs/config-file/config-basic#command-environment>, <https://learn.chatgpt.com/docs/config-file/config-reference>

### Keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `shell_environment_policy.inherit` | `all \| core \| none` | `all` | Baseline inheritance for spawned subprocesses |
| `shell_environment_policy.ignore_default_excludes` | bool | **`true`** | `true` = **skip** the automatic filter for names containing `KEY`, `SECRET`, `TOKEN`. Set `false` to apply it. |
| `shell_environment_policy.filters` | `map<string, include\|exclude>` | — | Canonical case-insensitive glob filters (`*`, `?`). Any `include` turns the whole thing into an allowlist. Keys merge case-insensitively across layers. |
| `shell_environment_policy.exclude` | `array<string>` | — | **Legacy.** Don't combine with `filters` in the same layer (Codex rejects it). |
| `shell_environment_policy.include_only` | `array<string>` | — | **Legacy** allowlist. Same warning. |
| `shell_environment_policy.set` | `map<string,string>` | `{}` | Explicit values injected **after** exclusions (so `set` can restore an excluded var; an include allowlist can still remove it) |
| `shell_environment_policy.experimental_use_profile` | bool | `false` | Spawn subprocesses through the user shell profile |

### Order of operations (verbatim)

> Codex applies automatic exclusions first, then custom exclusions, values from `set`, and finally the include-pattern allowlist. Because `set` runs after exclusions, it can restore an excluded variable. An include-pattern allowlist can still remove that restored value.

### The default is the dangerous one

Verbatim: "`ignore_default_excludes` defaults to `true`, so Codex doesn't automatically remove variable names containing `KEY`, `SECRET`, or `TOKEN`. Set it to `false` to apply those automatic exclusions before your explicit filters run."

Combined with `inherit = "all"` (the default), **out of the box `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` etc. are visible to every command the agent runs** (`env`, `printenv`, `echo $X`).

### Recommended shape

```toml
[shell_environment_policy]
inherit = "core"
ignore_default_excludes = false

[shell_environment_policy.filters]
"*KEY*"        = "exclude"
"*SECRET*"     = "exclude"
"*TOKEN*"      = "exclude"
"*PASSWORD*"   = "exclude"
"*CREDENTIAL*" = "exclude"
"AWS_*"        = "exclude"
"AZURE_*"      = "exclude"
"GOOGLE_*"     = "exclude"
"GCP_*"        = "exclude"
"GH_*"         = "exclude"
"GITHUB_*"     = "exclude"
"NPM_*"        = "exclude"
"DATABASE_URL" = "exclude"
```

Strict allowlist alternative (docs' own example — an `include` anywhere makes it allowlist-only):

```toml
[shell_environment_policy]
inherit = "none"
ignore_default_excludes = false

[shell_environment_policy.filters]
"PATH" = "include"
"HOME" = "include"
```

One-off CLI form (legacy array still works):

```shell
codex --config 'shell_environment_policy.include_only=["PATH","HOME"]'
```

**Caveat:** this governs environment inheritance for *spawned commands*. It does not stop the agent reading a secret out of a file and echoing it, and it does not apply to MCP server processes (those use `mcp_servers.<id>.env` / `env_vars`).

---

## 5. File-read exclusion mechanisms — and the gaps

### There is no `.codexignore`

Verified: GitHub code search for `codexignore` across `openai/codex` returns **0 results** (2026-08-30), and it is absent from the configuration reference. No documented ignore-file mechanism restricts what the model may read.

### `project_doc_max_bytes` is not a security control

It only caps how much of `AGENTS.md` is injected as project instructions (default 32 KiB). `project_doc_fallback_filenames` adds alternate filenames. Neither restricts tool reads.

### Permission profiles are the mechanism (beta)

<https://learn.chatgpt.com/docs/permissions>

Built-ins: `:read-only`, `:workspace`, `:danger-full-access`. Custom profiles under `[permissions.<name>]`, selected via top-level `default_permissions`. Switch at runtime with `/permissions`.

Access values, verbatim:

| Access | Meaning |
| --- | --- |
| `read` | "Allows commands to read files and list directories under the path. Commands cannot create, modify, rename, or delete files there." |
| `write` | "Allows commands to read and modify files under the path, including creating, renaming, and deleting files when the OS allows it." |
| `deny` | "**Denies both reads and writes** under the path. Use it to carve out a denied subpath from a broader `read` or `write` grant." |

Precedence, verbatim: "More specific entries override broader entries. When two entries target the same path, `deny` takes precedence over `write`, and `write` takes precedence over `read`."

Special path tokens: `:root` (filesystem root), `:minimal` ("Platform and runtime paths needed by common tools"), `:workspace_roots`, `:tmpdir`, `:slash_tmp`, `/absolute/path`, `~/path` (and `~\work`, `D:\work`, `\\server\share` on Windows).

**The canonical "deny reads outside the workspace" profile, verbatim from the docs:**

```toml
default_permissions = "workspace-only"

[permissions.workspace-only]
# By extending the :workspace profile, you get Codex's safeguards to ensure
# subfolders such as .codex/ and .git/ within a workspace root are read-only
# while the rest of the folder is writable.
extends = ":workspace"

[permissions.workspace-only.filesystem]
# By default, deny read access to all files on disk.
":root" = "deny"

# Though in practice, a software agent needs to be able to read folders that
# contain common tools, such as `/usr/bin`, to get work done, so grant access
# to a "minimal" set of files and folders, as determined by Codex.
":minimal" = "read"

# By extending the :workspace profile, :tmpdir and :slash_tmp are "write" by
# default, though you can deny access to them altogether, if desired.
":tmpdir" = "deny"
":slash_tmp" = "deny"
```

**Denying `.env` and key material** (docs example + `glob_scan_max_depth`):

```toml
[permissions.project-edit.filesystem]
glob_scan_max_depth = 3

[permissions.project-edit.filesystem.":workspace_roots"]
"." = "write"
".devcontainer" = "read"
"**/*.env" = "deny"
```

Notes on globs, verbatim:

> `deny` glob patterns are supported as deny-read rules. `read` or `write` globs are less portable on Linux, WSL, and native Windows sandboxing, so prefer exact paths or subtree rules such as `"docs/**" = "read"` when possible.
> On Linux, WSL, and native Windows, an unbounded `**` deny-read pattern may need bounded pre-expansion before the sandbox starts. Set `glob_scan_max_depth` when you use an unbounded pattern such as `"**/*.env" = "deny"`.
> If you prefer not to use bounded expansion, enumerate explicit depths such as `*.env`, `*/*.env`, and `*/*/*.env`.

Exact-path denies are recommended for stable locations: "Exact paths work well for stable locations such as `~/.ssh`." A narrower path can also reopen a subtree inside a broader deny:

```toml
[permissions.project-edit.filesystem]
"~/Documents" = "deny"
"~/Documents/codex" = "write"
```

**Hard blocker**, verbatim from the same page:

> Permission profiles do not compose with the older sandbox settings. Configure either `default_permissions` and `[permissions]`, or `sandbox_mode` / `sandbox_workspace_write`, but not both. **If `sandbox_mode` appears in any loaded config file, you pass `--sandbox`, or the selected config profile sets `sandbox_mode`, Codex uses those older sandbox settings instead of `default_permissions`.**

A leftover `sandbox_mode = "workspace-write"` in `~/.codex/config.toml` therefore silently disables your entire read-deny profile. This is the #1 thing a scanner should flag. (The one exception: managed `allowed_permission_profiles` forces profile mode.)

### Admin-enforced deny-read (`requirements.toml`)

<https://learn.chatgpt.com/docs/enterprise/managed-configuration#enforce-deny-read-requirements>

```toml
[permissions.filesystem]
deny_read = [
  # values can be absolute paths...
  "/**/*.env",
  # ...or relative to $HOME/%USERPROFILE% using `~`.
  "~/.ssh",
  # But relative paths starting with `./` are not allowed.
]
```

> Users can't weaken these requirements with local configuration.
> When deny-read requirements are present, the local runtime rejects full-access permissions and keeps local execution in a read-only or workspace sandbox so it can enforce them.
> **On native Windows, managed `deny_read` applies to direct file tools; shell subprocess reads don't use this sandbox rule.**

### Answering the direct question

> Does read-only sandbox still let the model `cat ~/.ssh/id_rsa`?

**Yes.** Under legacy `sandbox_mode = "read-only"` the whole filesystem is readable and `cat` is a read operation; with `approval_policy = "untrusted"` it counts as a "known-safe read operation" that runs automatically. Defenses, in rough order of strength:

1. Permission profile with `":root" = "deny"` / `"~/.ssh" = "deny"` (real sandbox enforcement).
2. Managed `requirements.toml` `[permissions.filesystem] deny_read` (user cannot weaken; weaker on native Windows for shell subprocesses).
3. `PreToolUse` hook returning `permissionDecision: "deny"` (docs: guardrail, not an enforcement boundary).
4. Execpolicy `forbidden` `prefix_rule` (prefix-matched; trivially evaded by shell metacharacters; scoped to commands run outside the sandbox).
5. OS-level isolation: devcontainer, VM, or a dedicated OS user with no access to your real dotfiles.

---

## 6. MCP servers, tool restriction, trust, hooks

### `[mcp_servers]`

<https://learn.chatgpt.com/docs/extend/mcp>

```toml
[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
env_vars = ["LOCAL_TOKEN"]          # allowlist of env vars to forward

[mcp_servers.context7.env]
MY_ENV_VAR = "MY_ENV_VALUE"          # explicit values
```

```toml
[mcp_servers.chrome_devtools]
url = "http://localhost:3000/mcp"
enabled_tools = ["open", "screenshot"]
disabled_tools = ["screenshot"] # applied after enabled_tools
default_tools_approval_mode = "prompt"
startup_timeout_sec = 20
tool_timeout_sec = 45
enabled = true

[mcp_servers.chrome_devtools.tools.open]
approval_mode = "approve"
```

Tool-restriction primitives:

- `enabled_tools: array<string>` — allowlist.
- `disabled_tools: array<string>` — denylist, "applied after `enabled_tools`".
- `default_tools_approval_mode: auto | prompt | writes | approve` — "`writes` prompts for tools that aren't marked read-only".
- `tools.<tool>.approval_mode` — per-tool override.
- `enabled = false` disables without deleting; `required = true` fails startup if the server can't init.
- Same shape for plugin-bundled servers under `plugins.<plugin>.mcp_servers.<server>`.

Secrets to MCP servers: `env_vars` is an allowlist ("Environment variables to allow and forward" / "Additional environment variables to whitelist for an MCP stdio server"); `bearer_token_env_var` names the var for `Authorization`; `env_http_headers` maps headers to env var names. Note `auth = "chatgpt"` reuses your ChatGPT session for the trusted first-party origin.

Admin allowlist (`requirements.toml`) matches **both name and identity**:

```toml
[mcp_servers.example.identity]
command = "npx"           # or a matcher table: executable + ordered arg matchers (exact|prefix|regex)
# url = "https://mcp.example.com/mcp"   # or exact|prefix|regex value matcher table
```

> If you configure an `mcp_servers` allowlist, the client enables an MCP server only when both its name and identity match an approved entry; otherwise, the client disables it.

Caveat: "The string form doesn't inspect arguments, `cwd`, `env`, or `env_vars`."

### Trust

```toml
[projects."/abs/path"]
trust_level = "untrusted"
```

> If you mark a project as untrusted, Codex skips project-scoped `.codex/` layers, including project-local config, hooks, and rules. User and system config still load, including user/global hooks and rules.

### Hooks

<https://learn.chatgpt.com/docs/hooks>

Locations: `~/.codex/hooks.json`, `~/.codex/config.toml` (`[hooks]`), `<repo>/.codex/hooks.json`, `<repo>/.codex/config.toml`, plus plugin-bundled hooks. Events: `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `UserPromptSubmit`, `Stop`.

Inline TOML form (verbatim from Advanced Config):

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = '/usr/bin/python3 "$(git rev-parse --show-toplevel)/.codex/hooks/pre_tool_use_policy.py"'
timeout = 30
statusMessage = "Checking Bash command"
```

Blocking a tool call from `PreToolUse` (stdout JSON):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive command blocked by hook."
  }
}
```

Legacy `{"decision":"block","reason":"…"}` and exit code `2` + stderr also work. `PermissionRequest` hooks can return `{"decision":{"behavior":"deny","message":"…"}}`; "If multiple matching hooks return decisions, any `deny` wins."

Trust model: "Before a non-managed hook can run, Codex requires you to review and trust the exact hook definition. Codex records trust against the hook's current hash, so new or changed hooks are marked for review and skipped until trusted." Manage via `/hooks`. Managed hooks (from `requirements.toml` + `hooks.managed_dir` / `hooks.windows_managed_dir`) are trusted by policy and cannot be disabled.

**Honest limitation, verbatim:**

> Some specialized tool paths can opt out of the default hook path. **Treat tool hooks as a useful guardrail, not a complete enforcement boundary.**

Hosted tools such as `WebSearch` do **not** use the local function-tool hook path (`PreToolUse`/`PostToolUse`: No). Background (`async: true`) hooks "can't block, approve, rewrite, or otherwise control the operation that triggered them."

Admin lockdown: `allow_managed_hooks_only = true` in `requirements.toml` (only there — "putting it in `config.toml` does not enable managed-hooks-only mode").

### Execpolicy rules

<https://learn.chatgpt.com/docs/agent-configuration/rules>

Starlark `.rules` files under `rules/` next to any active config layer (`~/.codex/rules/default.rules`, `<repo>/.codex/rules/*.rules` — trusted projects only). Scope statement: "Use rules to control which commands Codex can run **outside the sandbox**." Marked experimental.

```python
prefix_rule(
    pattern = ["curl"],
    decision = "prompt",
    justification = "Review requests to the approved cybersecurity target.",
)
```

`decision` ∈ `allow | prompt | forbidden`; most restrictive wins (`forbidden` > `prompt` > `allow`). Codex tree-sitter-splits simple `bash -lc "a && b"` chains (plain words joined by `&&`, `||`, `;`, `|`) and evaluates each command; it **does not split** scripts using redirection, `$(...)`, variable assignments, wildcards, or control flow — those are matched as one opaque `["bash","-lc","<full script>"]` invocation. Test with:

```shell
codex execpolicy check --pretty --rules ~/.codex/rules/default.rules -- gh pr view 7888
```

Note: "When Smart approvals are enabled (the default), Codex may propose a `prefix_rule` for you during escalation requests," and accepting an allowlist entry in the TUI writes to `~/.codex/rules/default.rules`.

### `notify`

```toml
notify = ["python3", "/path/to/notify.py"]
```

Fires only on `agent-turn-complete` today. The script receives one JSON argument with `type`, `thread-id`, `turn-id`, `cwd`, `input-messages`, `last-assistant-message`. **`notify` is ignored in project-local `.codex/config.toml`.** Distinct from `tui.notifications` / `tui.notification_method` / `tui.notification_condition`.

---

## 7. Data, privacy, telemetry

### Training eligibility by sign-in method

- **ChatGPT sign-in, individual plans (Free/Plus/Pro): training-eligible unless you opt out.** Verbatim, <https://help.openai.com/en/articles/5722486-how-your-data-is-used-to-improve-model-performance>: "When you use our services for individuals such as ChatGPT and Codex, we may use your content to train our models. You can opt out of training through our privacy portal by clicking on 'do not train on my content.' To turn off training for your ChatGPT conversations and Codex tasks, follow the instructions in our Data Controls FAQ."
- Verbatim, <https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan> ("Does OpenAI train on my Codex usage?"): "**Pro and Plus** — Conversations may be used to improve models unless you turn off training in ChatGPT data controls." And: "Your ChatGPT training data controls apply to content processed through Codex, including screenshots taken by Computer Use."
- **Separate Codex-only control:** "Codex has separate controls for allowing training on full environments, which you can manage in the Codex Settings. Note that adjusting your settings in the ChatGPT interface or privacy portal will not affect these full-environment Codex settings." (help article 5722486)
- **Business / Enterprise / Edu:** "By default, we do not train on any inputs or outputs from our products for business users, including ChatGPT Business, ChatGPT Enterprise, and the API." Mirrored in <https://learn.chatgpt.com/docs/enterprise/chatgpt-work-local-security>: "business data processed by covered OpenAI services is encrypted in transit and at rest and is not used to train or improve OpenAI models by default."
- **API key sign-in:** governed by your API org. Verbatim, <https://developers.openai.com/api/docs/guides/your-data>: "As of March 1, 2023, data sent to the OpenAI API is not used to train or improve OpenAI models (unless you explicitly opt in to share data with us)." Abuse-monitoring logs retained up to 30 days by default.

Opt-out path (<https://help.openai.com/en/articles/7730893-data-controls-faq>): Profile → Settings → Data Controls → turn off "Improve the model for everyone". Applies account-wide.

`auth.md` frames the split (<https://learn.chatgpt.com/docs/auth>): "When you sign in with ChatGPT, Codex usage follows your ChatGPT workspace permissions, role-based access control (RBAC), and ChatGPT Enterprise retention and residency settings. With an API key, usage follows your API organization's retention and data-sharing settings instead."

Admins can force the login method:

```toml
forced_login_method = "chatgpt"   # or "api"
forced_chatgpt_workspace_id = "00000000-0000-0000-0000-000000000000"
```

### ZDR / `disable_response_storage`

- **`disable_response_storage` no longer exists.** Absent from the configuration reference; GitHub code search returns **0 hits** across `openai/codex` (2026-08-30). Treat any config still containing it as stale/no-op. *(Evidence is absence-based — weaker than a positive statement, but corroborated by two independent sources.)*
- ZDR is an **API-organization** control, not a CLI setting: <https://developers.openai.com/api/docs/guides/your-data>. Verbatim: "Zero Data Retention changes some endpoint behavior: the `store` parameter for `/v1/responses` and `v1/chat/completions` will always be treated as `false`, even if the request attempts to set the value to `true`." Requires prior approval by OpenAI; configured at Settings → Organization → Data controls → Data Retention (org- and project-level).
- Data-residency base URL, if relevant: `openai_base_url = "https://us.api.openai.com/v1"`.

### Local data at rest

```toml
[history]
persistence = "none"      # "save-all" (default) | "none"
# max_bytes = 5242880
```

Default location `~/.codex/history.jsonl`. Also under `CODEX_HOME`: `config.toml`, `auth.json` (file-based creds), logs, session state, caches. `CODEX_SQLITE_HOME` / `sqlite_home` move SQLite-backed state.

```toml
cli_auth_credentials_store = "keyring"   # file | keyring | auto
```

> If you use file-based storage, treat `~/.codex/auth.json` like a password: it contains access tokens. Don't commit it, paste it into tickets, or share it in chat.

`log_dir` is unset by default; setting it "also enables the opt-in plaintext TUI log, `codex-tui.log`, in that directory." `codex login` writes `codex-login.log` to the log directory.

### Telemetry

OTel export is **off by default**.

```toml
[otel]
environment = "staging"   # dev | staging | prod
exporter = "none"          # none | otlp-http | otlp-grpc
log_user_prompt = false     # redact prompt text unless policy allows
```

Verbatim guidance: "Keep `log_user_prompt = false` unless policy explicitly permits storing prompt contents… Treat tool arguments and outputs as sensitive." Event categories include `codex.user_prompt` (length only unless enabled), `codex.tool_decision`, and `codex.tool_result` (which includes an "output snippet").

`otel.metrics_exporter` is documented as "defaults to `statsig`", while `exporter = "none"` "leaves instrumentation active but doesn't send data anywhere." *Unverified:* whether the default `statsig` metrics exporter transmits without explicit opt-in. Treat as an open question and pin it if your policy requires.

`otel` is ignored in project-local `.codex/config.toml`.

### Codex cloud

Verbatim: "Runs in isolated OpenAI-managed containers, preventing access to your host system or unrelated data. Uses a two-phase runtime model: setup runs before the agent phase and can access the network to install specified dependencies, then the agent phase runs offline by default unless you enable internet access for that environment. **Secrets configured for cloud environments are available only during setup and are removed before the agent phase starts.**"

### Web search

```toml
web_search = "cached"  # default; OpenAI-maintained index, no live fetch
# web_search = "indexed"
# web_search = "live"   # same as --search
# web_search = "disabled"
```

`--yolo` / full-access flips the default to `live`. `tools.web_search.allowed_domains` filters *search results*, not command network access, and does not restrict connectors or MCP servers.

---

## 8. What the model actually sees about your machine

Verified against source: <https://github.com/openai/codex/blob/main/codex-rs/core/src/context/world_state/environment.rs> and `codex-rs/core/src/context/environment_context.rs`.

Codex injects an `environment_context` fragment (role: `user`) containing:

- `<cwd>` — the **absolute native path** of the working directory. On Windows/macOS this leaks the OS username (`C:\Users\sebin\…`, `/Users/sebin/…`).
- `<shell>` — shell path; optionally `<shell_version>` (PowerShell version, obtained by actually running `$PSVersionTable.PSVersion.ToString()`).
- `<current_date>`, `<timezone>`.
- `<network enabled="true"><allowed>…</allowed><denied>…</denied></network>` — the effective domain allow/deny lists, comma-joined.
- `<filesystem><workspace_roots><root>…</root></workspace_roots><permission_profile type="managed"><file_system type="restricted" glob_scan_max_depth="N"><entry access="…">…</entry></file_system></permission_profile></filesystem>` — the model is told your workspace roots **and your permission rules, including deny paths**.
- `<subagents>` when configured. Multi-environment sessions render `<environments><environment id="…" primary="true|false">`.

It does **not** proactively dump env vars, hostname, IP addresses, or git remotes into this fragment. But:

- The model can trivially obtain all of that by running `env`, `hostname`, `ip a`, `whoami`, `git remote -v`, `cat /etc/hosts` — all permitted inside the sandbox unless denied.
- `notify` payloads include `cwd` and full user/assistant message text.
- Hook payloads include `cwd`, `session_id`, `transcript_path`, `model`, `permission_mode`, and full `tool_input`.
- `AGENTS.md` content is injected verbatim (up to `project_doc_max_bytes`) — don't put secrets or internal hostnames there.

**Residual exposure surfaces:** shell env (§4), file reads (§5), MCP servers (own process, own env, own network), web search (hosted, not proxied), apps/connectors, browser/Computer Use, and the client's own model/auth traffic. The command network proxy filters none of those.

---

## 9. Recommended hardened baseline

Two variants, because the two systems are mutually exclusive.

### A. Preferred — permission-profile based (Codex ≥ 0.138.0)

Put in `~/.codex/config.toml`. **Ensure `sandbox_mode` and `[sandbox_workspace_write]` appear nowhere in any loaded layer, and never pass `--sandbox`.**

```toml
# ---------- approvals ----------
approval_policy    = "on-request"   # or "untrusted" for maximum friction
approvals_reviewer = "user"         # "auto_review" adds a reviewer agent, not a boundary
allow_login_shell  = false          # don't source login shell profiles

# ---------- model / tools ----------
web_search = "cached"               # or "disabled"

[tools]
view_image = false                  # optional: drop the local image attachment tool

# ---------- permissions (replaces sandbox_mode) ----------
default_permissions = "hardened"

[permissions.hardened]
description = "Workspace-only writes; deny reads outside the workspace and to credential stores."
extends = ":workspace"              # keeps .git/.codex/.agents read-only inside roots

[permissions.hardened.filesystem]
":root"    = "deny"                 # default-deny reads across the disk
":minimal" = "read"                 # toolchain paths Codex deems necessary
":tmpdir"    = "deny"
":slash_tmp" = "deny"
glob_scan_max_depth = 4             # needed for unbounded ** deny globs on Linux/WSL/Windows

# Belt-and-braces exact denies: harmless under a :root deny, and they survive
# any future broadening of :minimal.
"~/.ssh"           = "deny"
"~/.aws"           = "deny"
"~/.config/gcloud" = "deny"
"~/.azure"         = "deny"
"~/.kube"          = "deny"
"~/.docker"        = "deny"
"~/.gnupg"         = "deny"
"~/.netrc"         = "deny"
"~/.npmrc"         = "deny"
"~/.pypirc"        = "deny"
"~/.codex"         = "deny"         # auth.json, history.jsonl
"~/.config/gh"     = "deny"

[permissions.hardened.filesystem.":workspace_roots"]
"." = "write"
"**/*.env"      = "deny"
"**/.env*"      = "deny"
"**/*.pem"      = "deny"
"**/*.key"      = "deny"
"**/*.p12"      = "deny"
"**/id_rsa*"    = "deny"
"**/secrets/**" = "deny"

[permissions.hardened.network]
enabled = false                     # flip to true only together with the proxy below

# ---------- network (only if you must) ----------
# [features]
# network_proxy = true              # REQUIRED for domain rules to be enforced
#
# [permissions.hardened.network.domains]
# "api.openai.com" = "allow"
# "registry.npmjs.org" = "allow"
# "**.github.com" = "allow"

# ---------- environment variables ----------
[shell_environment_policy]
inherit = "core"
ignore_default_excludes = false     # DO apply the built-in KEY/SECRET/TOKEN filter

[shell_environment_policy.filters]
"*KEY*"        = "exclude"
"*SECRET*"     = "exclude"
"*TOKEN*"      = "exclude"
"*PASSWORD*"   = "exclude"
"*CREDENTIAL*" = "exclude"
"*_PAT"        = "exclude"
"AWS_*"        = "exclude"
"AZURE_*"      = "exclude"
"GOOGLE_*"     = "exclude"
"GCP_*"        = "exclude"
"GH_*"         = "exclude"
"GITHUB_*"     = "exclude"
"NPM_*"        = "exclude"
"DATABASE_URL" = "exclude"
"OPENAI_*"     = "exclude"

# ---------- local data at rest ----------
cli_auth_credentials_store = "keyring"

[history]
persistence = "none"

[otel]
exporter = "none"
log_user_prompt = false

# ---------- project trust: opt in, don't default in ----------
# [projects."/abs/path/to/reviewed/repo"]
# trust_level = "trusted"
```

Verify:

```bash
codex --strict-config
codex sandbox macos  --permissions-profile hardened --log-denials -- cat "$HOME/.ssh/id_rsa"
codex sandbox linux  --permissions-profile hardened -- cat "$HOME/.ssh/id_rsa"
codex execpolicy check --pretty --rules ~/.codex/rules/default.rules -- curl https://example.com
# In session: /status (workspace dirs), /permissions (active profile), /hooks (hook trust)
```

### B. Fallback — legacy `sandbox_mode` (older clients)

This **cannot** stop reads. Only use it with an outer boundary (devcontainer, VM, dedicated OS user without access to your real dotfiles).

```toml
approval_policy   = "untrusted"
sandbox_mode      = "workspace-write"
allow_login_shell = false
web_search        = "cached"

[sandbox_workspace_write]
network_access = false
exclude_slash_tmp = true
exclude_tmpdir_env_var = true
writable_roots = []

[shell_environment_policy]
inherit = "core"
ignore_default_excludes = false

[shell_environment_policy.filters]
"*KEY*"    = "exclude"
"*SECRET*" = "exclude"
"*TOKEN*"  = "exclude"
"AWS_*"    = "exclude"

[history]
persistence = "none"

[windows]
sandbox = "elevated"
```

Reference outer boundary: <https://github.com/openai/codex/tree/main/.devcontainer> (`devcontainer.secure.json`, `Dockerfile.secure`, `init-firewall.sh`). Docs caveat, verbatim: "If you run Codex with `--sandbox danger-full-access` … inside the container, a malicious project can exfiltrate anything available inside the devcontainer, including Codex credentials."

### C. Org-enforced floor (`requirements.toml`)

`/etc/codex/requirements.toml` (Unix) or `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows):

```toml
allowed_approval_policies = ["untrusted", "on-request"]

[allowed_permission_profiles]
":read-only" = true
":workspace" = true
# ":danger-full-access" omitted => denied, including future profiles
"hardened" = true

default_permissions = "hardened"

[permissions.filesystem]
deny_read = [
  "/**/*.env",
  "~/.ssh",
  "~/.aws",
  "~/.config/gcloud",
]

allow_managed_hooks_only = true

[features]
network_proxy = true

[experimental_network]
enabled = true
managed_allowed_domains_only = true
domains = { "api.openai.com" = "allow" }
```

Legacy compatibility form for mixed fleets (blocks `--yolo` and `-a never`), verbatim from the docs:

```toml
allowed_approval_policies = ["untrusted", "on-request"]
allowed_sandbox_modes = ["read-only", "workspace-write"]
```

---

## Known gaps / caveats

1. **Legacy sandbox modes do not restrict reads at all.** `read-only` and `workspace-write` both compile to `(allow file-read*)` on macOS and the equivalent elsewhere. Any secret readable by your user is readable by the agent, with no prompt. (Verified in source; the docs never state this plainly.)
2. **Permission profiles and `sandbox_mode` are mutually exclusive, and `sandbox_mode` silently wins.** A stray `sandbox_mode` in *any* loaded layer — user config, a `--profile` file, a trusted project's `.codex/config.toml` — or a single `--sandbox` flag disables `default_permissions` entirely. Fail-open, not fail-closed.
3. **Permission profiles are labeled beta:** "Permission profiles are under active development and may change."
4. **Secrets in env are inherited by default.** `ignore_default_excludes = true` (default) means no automatic `KEY`/`SECRET`/`TOKEN` filtering, and `inherit` defaults to `all`.
5. **No `.codexignore`.** Repo authors cannot mark `.env` unreadable for visitors' Codex sessions except via a `.codex/config.toml` permission profile, which only applies once the project is trusted.
6. **Project config outranks user config.** A committed `.codex/config.toml` in a trusted repo can set `approval_policy`, `sandbox_mode`, `[permissions]`, `[mcp_servers]`, `[features]`, `[hooks]`. Only provider/notify/otel/profile keys are ignored. Hooks additionally need per-hash trust, which `--dangerously-bypass-hook-trust` skips.
7. **Enabling network without the proxy = unrestricted egress.** `network.enabled = true` or `sandbox_workspace_write.network_access = true` with `features.network_proxy` off gives direct outbound access; domain rules are silently not enforced.
8. **The network proxy covers only sandboxed commands.** Web search, apps/connectors, MCP servers, browser/Computer Use, Codex cloud, and Codex's own model/auth traffic all bypass it.
9. **DNS rebinding is only partially mitigated:** "The check reduces DNS rebinding risk, but it does not eliminate it."
10. **Hooks are not an enforcement boundary.** "Some specialized tool paths can opt out of the default hook path. Treat tool hooks as a useful guardrail, not a complete enforcement boundary." Hosted tools bypass hooks entirely; `async` hooks cannot block; multiple matching hooks run concurrently so one can't pre-empt another.
11. **Execpolicy rules are prefix-based and only shell-aware for simple chains.** Anything with `$(...)`, redirection, variables, or wildcards is matched as one opaque `bash -lc "<script>"`, so command denylists are easy to evade. Scoped by their own docs to commands run *outside* the sandbox. Marked experimental.
12. **`--ignore-user-config` and `--ignore-rules` bypass your hardening** for a single run; `--dangerously-bypass-hook-trust` bypasses hook review.
13. **Native Windows `unelevated` sandbox is weaker:** "weaker network isolation and cannot enforce every split read/write carveout." Managed `deny_read` on native Windows "applies to direct file tools; shell subprocess reads don't use this sandbox rule." Prefer WSL2.
14. **The Linux sandbox can silently be unavailable.** Missing `bwrap` or blocked user namespaces (containers, AppArmor) force compatibility paths; Codex warns at startup, but a user who then reaches for `--sandbox danger-full-access` to "make it work" has removed the boundary.
15. **Unbounded `**` deny globs need `glob_scan_max_depth`** on Linux/WSL/Windows; a `.env` nested deeper than the configured depth is **not** denied. Enumerate explicit depths if you need certainty.
16. **`.git` is write-protected, not read-protected.** Credentials embedded in `.git/config` remotes (e.g. `https://user:token@host`) remain readable.
17. **Consumer ChatGPT sign-in is training-eligible by default**, and the "train on full environments" Codex setting is *separate* from the ChatGPT data-controls toggle and the privacy portal.
18. **`disable_response_storage` is gone** — verified only by absence from the config reference and zero GitHub code-search hits. Non-storage requires an API-org ZDR arrangement.
19. **`otel.metrics_exporter` defaults to `statsig`.** *Unverified* whether that transmits anything without explicit opt-in. Set `[otel] exporter = "none"` and consider pinning `metrics_exporter = "none"` if your policy demands it.
20. **MCP stdio child-process default environment is undocumented.** *Unverified.* Pin `env` / `env_vars` explicitly rather than assuming a safe default.
21. **The model is told your workspace roots, deny rules, and domain allowlist.** Deliberate (so it doesn't waste turns), but an adversarial prompt-injection payload learns exactly which boundaries to probe.
22. **`--add-dir` grants write**, and "Smart approvals" (default on) may propose a `prefix_rule` during escalation; accepting one writes a persistent allow rule to `~/.codex/rules/default.rules`.
23. **`approvals_reviewer = "auto_review"` removes the human**, and by its own docs "Auto-review doesn't inspect routine actions that are already permitted inside the sandbox. With `approval_policy = \"never\"` or Full Access, a sensitive action might not create a reviewable approval request."

---

## Detection checklist

Scan `~/.codex/config.toml`, `~/.codex/*.config.toml`, `/etc/codex/config.toml`, `/etc/codex/managed_config.toml`, `~/.codex/managed_config.toml`, every `<repo>/.codex/config.toml` from project root to cwd, `<repo>/.codex/hooks.json`, `<repo>/.codex/rules/*.rules`, `<repo>/AGENTS.md`, and any committed scripts/CI that invoke `codex`.

### Critical — treat as unhardened

| Signal | Why |
| --- | --- |
| `sandbox_mode = "danger-full-access"` | No filesystem or network boundary |
| `approval_policy = "never"` with any write-capable sandbox | No human gate |
| `default_permissions = ":danger-full-access"` | Same |
| `--yolo` / `--dangerously-bypass-approvals-and-sandbox` in scripts, CI, Makefile, `package.json`, `.github/workflows` | No boundary |
| `default_permissions` present **and** `sandbox_mode` / `[sandbox_workspace_write]` present anywhere in the layer stack | The read-deny profile is silently inert |
| `permissions.<x>.filesystem` with `":root" = "read"` and no narrower denies | Whole disk readable |
| `network_access = true` (or `network.enabled = true`) **without** `features.network_proxy` (or enabled `[experimental_network]`) | Unrestricted egress; domain rules unenforced |
| `features.network_proxy.domains` containing `"*" = "allow"` | Effectively open egress |
| `dangerously_allow_non_loopback_proxy = true` or `dangerously_allow_all_unix_sockets = true` | Deliberate boundary widening |
| `--dangerously-bypass-hook-trust`, `--ignore-user-config`, `--ignore-rules` in any committed script | Bypasses configured guardrails |
| `auth.json`, `history.jsonl`, rollout/transcript files, or any `.codex/` state tracked by git | Credential / transcript leak |

### High — missing key protections

| Signal | Why |
| --- | --- |
| No `[shell_environment_policy]` at all | Defaults to `inherit = "all"` + no secret-name filtering |
| `ignore_default_excludes` absent or `= true` | KEY/SECRET/TOKEN vars forwarded to every command |
| `inherit = "all"` with no `filters` / `exclude` / `include_only` | Full env exposure |
| No `deny` covering `.env`, `*.pem`, `*.key`, `id_rsa*` under `:workspace_roots` | `.env` readable |
| No `deny` for `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.codex` | Credential stores readable |
| Unbounded `**` deny globs with no `glob_scan_max_depth` (Linux/WSL/Windows) | Deep matches not denied |
| `approval_policy = { granular = { … } }` with all categories `true` plus `approvals_reviewer = "auto_review"` | Human fully out of the approval loop |
| `[projects."…"] trust_level = "trusted"` for repos the user doesn't control | Project `.codex/` layer (config + hooks + rules) becomes active and outranks user config |
| `[mcp_servers.*]` with no `enabled_tools` / `disabled_tools` / `default_tools_approval_mode` | Unbounded tool surface |
| `mcp_servers.<id>.env` with literal secret values, or `env_vars` listing credential vars | Secrets handed to third-party processes |
| `[hooks]` / `hooks.json` in a repo, especially `SessionStart` / `UserPromptSubmit` command hooks | Code executed on session start |
| `windows.sandbox = "unelevated"` on native Windows | Weaker isolation; prefer `elevated` or WSL2 |
| Linux/WSL without `bubblewrap` installed | Sandbox may degrade or fail |
| `writable_roots` / `--add-dir` pointing outside the repo (`~`, `/`, `~/.config`) | Write escape |

### Medium — privacy / hygiene

| Signal | Why |
| --- | --- |
| `history.persistence` absent or `= "save-all"` | Transcripts on disk under `CODEX_HOME` |
| `otel.log_user_prompt = true` | Raw prompt text exported |
| `otel.exporter` pointed at a third-party endpoint | Prompt/tool data leaving the org |
| `cli_auth_credentials_store = "file"` | Tokens in `~/.codex/auth.json` |
| `log_dir` set | Enables plaintext `codex-tui.log` |
| `web_search = "live"` or `--search` | Live untrusted content → prompt-injection surface |
| `AGENTS.md` containing hostnames, internal URLs, credentials, or instructions to read `.env` | Injected verbatim into model context |
| `approval_policy = "on-failure"` | Deprecated value |
| `disable_response_storage` present | Stale/no-op key; config is out of date |
| `--full-auto` in scripts | Deprecated; warns |
| No `requirements.toml` on a managed fleet | No enforceable floor; users can self-downgrade |

### Positive signals — evidence of hardening

- `default_permissions` naming a custom profile that `extends = ":workspace"` or `":read-only"` **and** sets `":root" = "deny"` + `":minimal" = "read"`, with **no** `sandbox_mode` anywhere in the stack.
- `[permissions.<x>.filesystem.":workspace_roots"]` containing `"**/*.env" = "deny"` plus a `glob_scan_max_depth`.
- `shell_environment_policy.inherit` = `"core"` or `"none"` **and** `ignore_default_excludes = false` **and** explicit exclude filters.
- `approval_policy = "on-request"` or `"untrusted"`; `allow_login_shell = false`.
- `features.network_proxy.enabled = true` with a scoped `domains` allowlist and `allow_local_binding` unset/false.
- `[history] persistence = "none"`; `[otel] log_user_prompt = false`; `cli_auth_credentials_store = "keyring"`.
- `requirements.toml` with `allowed_permission_profiles` omitting `:danger-full-access`, `allowed_approval_policies` omitting `never`, `[permissions.filesystem] deny_read`, and `allow_managed_hooks_only = true`.
- Repo ships `.devcontainer/devcontainer.secure.json` (Codex's reference hardened devcontainer).
- `--strict-config` used in automation (catches typo'd hardening keys that would otherwise be silently ignored).
- `[projects."…"] trust_level = "untrusted"` for third-party checkouts.

---

## Source index

| Topic | URL |
| --- | --- |
| Docs index (machine-readable) | <https://learn.chatgpt.com/llms.txt> |
| Config basics + precedence | <https://learn.chatgpt.com/docs/config-file/config-basic> |
| Advanced config (profiles, shell env policy, notify, history, hooks locations) | <https://learn.chatgpt.com/docs/config-file/config-advanced> |
| Full key reference (`config.toml` + `requirements.toml`) | <https://learn.chatgpt.com/docs/config-file/config-reference> |
| Sample config | <https://learn.chatgpt.com/docs/config-file/config-sample> |
| Environment variables Codex reads | <https://learn.chatgpt.com/docs/config-file/environment-variables> |
| Approvals, sandbox, network, protected paths, OTel | <https://learn.chatgpt.com/docs/agent-approvals-security> |
| Sandbox concepts + OS prerequisites | <https://learn.chatgpt.com/docs/sandboxing> |
| Auto-review | <https://learn.chatgpt.com/docs/sandboxing/auto-review> |
| Permission profiles (read denial) | <https://learn.chatgpt.com/docs/permissions> |
| Hooks | <https://learn.chatgpt.com/docs/hooks> |
| Execpolicy rules | <https://learn.chatgpt.com/docs/agent-configuration/rules> |
| AGENTS.md | <https://learn.chatgpt.com/docs/agent-configuration/agents-md> |
| MCP | <https://learn.chatgpt.com/docs/extend/mcp> |
| Authentication / credential storage | <https://learn.chatgpt.com/docs/auth> |
| Managed configuration (`requirements.toml`, `managed_config.toml`, MDM) | <https://learn.chatgpt.com/docs/enterprise/managed-configuration> |
| OpenAI's own hardening guidance | <https://learn.chatgpt.com/docs/cyber-safety/recommended-configuration> |
| Enterprise local security / no-training-by-default | <https://learn.chatgpt.com/docs/enterprise/chatgpt-work-local-security> |
| API data controls / ZDR | <https://developers.openai.com/api/docs/guides/your-data> |
| Training on individual-plan Codex data | <https://help.openai.com/en/articles/5722486-how-your-data-is-used-to-improve-model-performance> |
| Codex + ChatGPT plan FAQ ("Does OpenAI train on my Codex usage?") | <https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan> |
| Data Controls FAQ (opt-out path) | <https://help.openai.com/en/articles/7730893-data-controls-faq> |
| Sandbox policy source (read semantics) | <https://github.com/openai/codex/blob/main/codex-rs/protocol/src/permissions.rs> |
| Seatbelt profile generation | <https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt.rs> |
| Seatbelt base policy | <https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt_base_policy.sbpl> |
| Environment context sent to the model | <https://github.com/openai/codex/blob/main/codex-rs/core/src/context/world_state/environment.rs> |
| Default auto-review policy | <https://github.com/openai/codex/blob/main/codex-rs/core/src/guardian/policy.md> |
| Reference hardened devcontainer | <https://github.com/openai/codex/tree/main/.devcontainer> |
