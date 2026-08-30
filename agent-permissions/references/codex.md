# Codex CLI: hardening reference
Verified against: learn.chatgpt.com docs at 2026-08-30; Codex **0.138.0+** (permission profiles), **0.134.0+** (profiles became separate files), **0.115+** (Linux sandbox moved to `bwrap`).

## Config surfaces

Layer stack, **highest precedence first**: (1) CLI flags and `--config`; (2) project `.codex/config.toml`, root→cwd, closest wins, **trusted projects only**; (3) `--profile NAME` file; (4) `~/.codex/config.toml`; (5) `/etc/codex/config.toml`; (6) defaults. Above all of it: managed defaults, which "override the user's local `config.toml` and any CLI `--config` overrides", then admin `requirements.toml`, which *constrains legal values*; conflicting values fall back to a compatible one and the user is notified.

| File | Scope | Committed? | Precedence / trust notes |
|---|---|---|---|
| `/etc/codex/requirements.toml` · `%ProgramData%\OpenAI\Codex\requirements.toml` | org | no | Hard floor; users cannot weaken. Only place `allow_managed_hooks_only` works. |
| `/etc/codex/managed_config.toml` · `~/.codex/managed_config.toml` (Windows) · MDM `com.openai.codex` | machine | no | Managed defaults; beat user config and `--config`. |
| `~/.codex/config.toml` (`$CODEX_HOME/config.toml`) | user | no | Main hardening file. Skipped for one run by `--ignore-user-config`. |
| `~/.codex/NAME.config.toml` | user | no | Profile layer via `--profile NAME`. Since 0.134.0 `[profiles.NAME]` in `config.toml` and top-level `profile =` are **gone**. |
| `<repo>/.codex/config.toml` | repo | **yes** | Root→cwd, closest wins, **outranks user config**, trusted projects only. Primary scan target. |
| `.codex/hooks.json` / `[hooks]`, and `.codex/rules/*.rules` (repo and `~/.codex/`) | repo/user | yes | Hooks = command execution in the agent loop; non-managed hooks need per-hash trust via `/hooks`, skipped by `--dangerously-bypass-hook-trust`. Rules = Starlark execpolicy, experimental, skipped by `--ignore-rules`. |
| `AGENTS.md` / `AGENTS.override.md` (repo dirs and `$CODEX_HOME`) | repo/user | yes | Injected verbatim, capped by `project_doc_max_bytes` (32 KiB). One file per dir, concatenated root-first, closest wins. |
| `~/.codex/auth.json`, `history.jsonl`, logs, SQLite state | user | **never** | Tokens and transcripts under `CODEX_HOME`. |

A repo `.codex/config.toml` **cannot** set (verbatim ignore list, warns at startup): `openai_base_url`, `chatgpt_base_url`, `apps_mcp_product_sku`, `model_provider`, `model_providers`, `notify`, `profile`, `profiles`, `experimental_realtime_ws_base_url`, `otel`. It therefore **can** set `approval_policy`, `sandbox_mode`, `[sandbox_workspace_write]`, `default_permissions`, `[permissions]`, `[mcp_servers]`, `[features]`, `[hooks]`: a trusted repo can downgrade the sandbox and approvals.

Trust gate: `[projects."/abs/path"] trust_level = "trusted" | "untrusted"`. Untrusted skips **all** project `.codex/` layers (config, hooks, rules); user/system layers still load. `project_root_markers` (default `[".git", ".hg", ".sl"]`) sets where the walk-up starts; `[]` disables it.

## What each control actually stops

| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `sandbox_mode = "read-only"` | T1 | All writes; all network | **Any read**: the whole filesystem is readable with no prompt |
| `sandbox_mode = "workspace-write"` | T1 | Writes outside workspace roots + `$TMPDIR` + `/tmp` + `writable_roots`; writes to `<root>/.git`, `.agents`, `.codex`; network unless `network_access = true` | **Any read**, incl. `.git/config` remotes with embedded tokens |
| `sandbox_mode = "danger-full-access"` | - | Nothing | Everything. Only acceptable inside an external boundary |
| Permission profile (`default_permissions` + `[permissions.<n>]`) | T1 | The **only** local read-deny: `":root" = "deny"` plus targeted `deny` paths/globs, enforced by the OS sandbox | Anything at all if any layer sets `sandbox_mode` or `--sandbox` is passed (profile silently inert); matches deeper than `glob_scan_max_depth`; beta, "may change" |
| `approval_policy = "untrusted"` / `"on-request"` | T4 | `untrusted`: state-mutating commands, destructive git, git output/config-override flags. `on-request`: escapes beyond the sandbox boundary | "known-safe read operations", which run automatically, including `cat` of a credential file; anything already permitted inside the sandbox |
| `approval_policy = "never"` | - | Nothing | Works with any sandbox mode; no human gate at all |
| `approval_policy = { granular = {…} }` | T4 | Per category (`sandbox_approval`, `rules`, `mcp_elicitations`, `request_permissions`, `skill_approval`): `false` **auto-rejects**, fail-closed | Categories set `true` are still click-through prompts |
| `approvals_reviewer = "auto_review"` | - | Nothing new: a subagent replaces the human on already-gated actions | "doesn't change the sandbox boundary"; with `never` or full access a sensitive action may never surface. Build/review/parse failures and timeouts fail closed |
| `shell_environment_policy` | T3 | Named env vars reaching spawned commands (`inherit`, `filters`, `set`) | Secrets read out of files; MCP servers (they use `mcp_servers.<id>.env` / `env_vars`) |
| `features.network_proxy` + `domains` | T2 | Direct outbound from sandboxed commands to non-allowlisted hosts; loopback/private when `allow_local_binding = false` | Web search, apps/connectors, MCP connections, browser/Computer Use, Codex cloud, Codex's own model/auth traffic. DNS rebinding only partially |
| Lifecycle hooks (`PreToolUse` deny, `PermissionRequest` deny) | T5 | Whatever the script expresses; any `deny` among matching hooks wins | Hosted tools (e.g. `WebSearch`) bypass the local hook path; `async: true` hooks cannot block; verbatim "a useful guardrail, not a complete enforcement boundary" |
| `requirements.toml` `[permissions.filesystem] deny_read` | T1 (admin) | Reads of listed paths; users cannot weaken; forces the runtime to reject full-access and stay in a read-only/workspace sandbox | On **native Windows** applies only to direct file tools: "shell subprocess reads don't use this sandbox rule" |
| Execpolicy `.rules` (`prefix_rule` `forbidden`/`prompt`) | T4 | Prefix-matched commands run **outside** the sandbox; most restrictive wins | Anything with `$(…)`, redirection, variable assignment, wildcards or control flow (matched as one opaque `bash -lc "<script>"`) |
| MCP `enabled_tools` / `disabled_tools` / `default_tools_approval_mode` / `tools.<t>.approval_mode` | T4 | Tools outside the allowlist (`disabled_tools` applied after `enabled_tools`) | The server process: its own env, its own network, unfiltered by the proxy |
| `requirements.toml` `[mcp_servers.<n>.identity]` | T4 (admin) | Servers whose name **and** identity don't both match are disabled | String form "doesn't inspect arguments, `cwd`, `env`, or `env_vars`" |
| `AGENTS.md`, `project_doc_max_bytes` | T7 | Nothing; caps injection volume, not tool reads | Any tool call. No T6 tier exists here: **there is no `.codexignore`** |

## Rule semantics you must get right

1. **`read-only` and `workspace-write` both grant filesystem-wide READ.** Source, not docs: `codex-rs/protocol/src/permissions.rs` (`impl From<&SandboxPolicy> for FileSystemSandboxPolicy`) maps `ReadOnly` → `FileSystemSpecialPath::Root = Read` and `WorkspaceWrite` → `Root = Read` plus write roots; `has_full_disk_read_access()` returns `true`; `codex-rs/sandboxing/src/seatbelt.rs` emits `(allow file-read*)` on top of the `(deny default)` base in `seatbelt_base_policy.sbpl`. `cat ~/.ssh/id_rsa`, `~/.aws/credentials`, `../other-repo/.env`, `~/.codex/auth.json` all succeed with no prompt.
2. **Permission profiles are the only local read-deny, and `sandbox_mode` silently wins.** Verbatim: "If `sandbox_mode` appears in any loaded config file, you pass `--sandbox`, or the selected config profile sets `sandbox_mode`, Codex uses those older sandbox settings instead of `default_permissions`." Fail-open. One stray `sandbox_mode` in the user file, a `--profile` file, or a trusted repo's config kills the whole read-deny profile. Sole exception: managed `allowed_permission_profiles` forces profile mode.
3. **Access values:** `read` (read + list, no mutation), `write` (read + create/rename/delete), `deny` (**denies reads and writes**). More specific overrides broader; at the same path `deny` > `write` > `read`, so a narrower `write` reopens a subtree inside a broader `deny`. Tokens: `:root`, `:minimal`, `:workspace_roots`, `:tmpdir`, `:slash_tmp`, absolute paths, `~/path`, and `~\work`, `D:\work`, `\\server\share` on Windows. Built-ins: `:read-only`, `:workspace`, `:danger-full-access`; switch at runtime with `/permissions`.
4. **Deny globs need `glob_scan_max_depth`.** Only `deny` globs are portable; `read`/`write` globs are "less portable on Linux, WSL, and native Windows"; prefer exact paths or `"docs/**" = "read"`. An unbounded `**` deny needs bounded pre-expansion; a `.env` deeper than the configured depth is **not denied**. Alternative: enumerate `*.env`, `*/*.env`, `*/*/*.env`.
5. **`shell_environment_policy` defaults are the dangerous ones:** `inherit = "all"` and `ignore_default_excludes = true`, i.e. the built-in `KEY`/`SECRET`/`TOKEN` filter is **OFF by default**, so `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` reach every command. Set `ignore_default_excludes = false` explicitly. Order: automatic exclusions → custom exclusions → `set` → include allowlist; `set` can restore an excluded var, an include allowlist can still remove it. Any `include` in `filters` makes the whole map an allowlist. `exclude`/`include_only` are legacy arrays, rejected if combined with `filters` in the same layer.
6. **Deprecated / removed:** `approval_policy = "on-failure"` (parsed, do not use); `--full-auto` (deprecated compatibility path, prints a warning); `[profiles.x]` and top-level `profile =` (removed 0.134.0); `disable_response_storage` (zero code hits, absent from the reference: any config containing it is stale/no-op; non-storage needs an API-org ZDR arrangement, not a CLI flag). **No `.codexignore`** either (0 hits across `openai/codex`, 2026-08-30): no read-exclusion exists outside permission profiles and managed `deny_read`, and `project_doc_max_bytes` / `project_doc_fallback_filenames` are not security controls.
7. **`.git` is write-protected, not read-protected** in writable roots (recursive, and follows a `gitdir:` pointer file); `https://user:token@host` remotes stay readable. Extending `:workspace` keeps the root's `.codex` read-only unless explicitly overridden.
8. **Network truth table:** off + proxy on → stays off, feature does nothing. On + proxy off → **unrestricted direct outbound**, domain rules silently unenforced. On + proxy on → constrained. Matching: allowlist-first; exact hosts match only themselves; `*.example.com` = subdomains not apex; `**.example.com` = apex + subdomains; global `*` allow matches any non-denied public host; `deny` always wins; `*` is allow-only. Proxy defaults: `enabled=false`, `domains` unset, `allow_local_binding=false`, `allow_upstream_proxy=true`, `dangerously_allow_non_loopback_proxy=false`, `dangerously_allow_all_unix_sockets=false`.
9. **Sign-in method decides training eligibility.** ChatGPT consumer plans (Free/Plus/Pro) are training-eligible unless the user opts out (Settings → Data Controls → "Improve the model for everyone", account-wide). Codex has a **separate** "train on full environments" toggle in Codex Settings; verbatim: "adjusting your settings in the ChatGPT interface or privacy portal will not affect these full-environment Codex settings." Business/Enterprise/Edu and API-key usage are not trained on by default. Admins can pin `forced_login_method` / `forced_chatgpt_workspace_id`.
10. **OS enforcement:** macOS = Seatbelt via `sandbox-exec -p`; if a policy can't be enforced Codex refuses to run rather than running unsandboxed. Linux/WSL = `bwrap` + `seccomp`, **with Landlock as a compatibility fallback**; strongest path needs user namespaces and kernel support, restricted container hosts force compatibility paths, unsupported split policies are refused; needs `bubblewrap` on `PATH` (Ubuntu 24.04 may need the `bwrap-userns-restrict` AppArmor profile). **WSL1 supported through 0.114, dropped at 0.115.**
11. **Windows:** native Windows has its own sandbox. `[windows] sandbox = "elevated"` is strongest (lower-privilege sandbox users, filesystem boundaries, firewall rules); `"unelevated"` is a fallback with "weaker network isolation and cannot enforce every split read/write carveout". Prefer WSL2; for the IDE extension set `"chatgpt.runCodexInWindowsSubsystemForLinux": true`.
12. **Single-run bypasses:** `--ignore-user-config` (auth still uses `CODEX_HOME`), `--ignore-rules`, `--dangerously-bypass-hook-trust`, `--sandbox` (kills profiles), `--dangerously-bypass-approvals-and-sandbox`/`--yolo` (also flips `web_search` to `live`). `--add-dir` grants **write**. `--strict-config` is the opposite: errors on unrecognized fields, catching typo'd hardening keys.
13. **The model is told your boundaries.** `environment_context` includes absolute `cwd` (leaks the OS username), shell + version, network allow/deny lists, workspace roots, and the permission profile's entries **including deny paths**. It doesn't dump env/hostname/remotes, but the agent can run `env`, `hostname`, `git remote -v` unless denied. Smart approvals (default on) may propose a `prefix_rule`; accepting it writes a persistent allow rule to `~/.codex/rules/default.rules`.
14. **Two open questions.** MCP stdio child-process default environment is undocumented **[UNVERIFIED]**; pin `env`/`env_vars` explicitly rather than assuming a safe default. `otel.metrics_exporter` is documented as defaulting to `statsig`; whether it transmits without explicit opt-in is **[UNVERIFIED]**; `exporter = "none"` "leaves instrumentation active but doesn't send data anywhere", so pin `metrics_exporter = "none"` if policy demands. `otel` is ignored in project-local config.

## Detection checklist

Repo-visible: `<repo>/.codex/**`, `AGENTS.md`, scripts, CI.

| Check | Severity | What it means |
|---|---|---|
| `--yolo` / `--dangerously-bypass-approvals-and-sandbox` in scripts, Makefile, `package.json`, workflows, outside a container | Critical | No boundary at all |
| `sandbox_mode = "danger-full-access"` or `default_permissions = ":danger-full-access"` | Critical | No filesystem or network boundary |
| `approval_policy = "never"` with any write-capable sandbox | Critical | No human gate |
| `--ignore-user-config`, `--ignore-rules`, `--dangerously-bypass-hook-trust` in a committed script; or `auth.json`/`history.jsonl`/`.codex/` state tracked by git | Critical | Bypasses the user's guardrails; credential and transcript leak |
| `sandbox_mode` or `[sandbox_workspace_write]` present alongside `default_permissions` | High | The read-deny profile is **silently inert** |
| `[hooks]` / `.codex/hooks.json` in the repo, especially `SessionStart` / `UserPromptSubmit` | High | Code executes on session start once the hash is trusted |
| `[mcp_servers.*]` with no tool allowlist/approval mode, or `env` with literal secrets / `env_vars` listing credential vars | High | Unbounded third-party surface; secrets outside the proxy |
| `network_access = true` (or `network.enabled = true`) with no `features.network_proxy`; `domains` with `"*" = "allow"`; `dangerously_allow_*` true | High | Unrestricted egress; domain rules unenforced |
| `writable_roots` or `--add-dir` pointing outside the repo (`~`, `/`, `~/.config`) | High | Write escape |
| Broad `allow` `prefix_rule`s in `.codex/rules/*.rules`; `AGENTS.md` holding hostnames, credentials, or "read `.env`" instructions | Medium | Persistent auto-approvals; verbatim-injected content |
| `approval_policy = "on-failure"`, `--full-auto`, `[profiles.x]`, `disable_response_storage` | Low | Deprecated/removed: stale config, silently ignored |

User: `~/.codex/config.toml`, `~/.codex/*.config.toml`, `/etc/codex/config.toml`, `managed_config.toml`.

| Check | Severity | What it means |
|---|---|---|
| `approval_policy = "never"` or `sandbox_mode = "danger-full-access"` | Critical | Unhardened |
| Any `sandbox_mode` present while a permission profile is configured | High | Profile inert (semantics #2) |
| No permission profile, relying on `sandbox_mode` for read protection | High | **Reads are not restricted at all**; every credential file on disk is readable, unprompted |
| `permissions.<x>.filesystem` with `":root" = "read"` and no narrower denies | High | Whole disk readable |
| `[shell_environment_policy]` absent, or `ignore_default_excludes` absent/`true`, or `inherit = "all"` with no filters | High | `KEY`/`SECRET`/`TOKEN` vars forwarded to every command |
| No `deny` for `**/*.env`, `*.pem`, `*.key`, `id_rsa*` under `:workspace_roots`; none for `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.codex` | High | Repo secrets and credential stores readable |
| Unbounded `**` deny globs with no `glob_scan_max_depth` (Linux/WSL/Windows) | High | Deep matches not denied |
| `trust_level = "trusted"` for repos the user doesn't control | High | Project config + hooks + rules activate and outrank user config |
| `granular` approvals with every category `true` plus `approvals_reviewer = "auto_review"` | High | Human fully out of the approval loop |
| `windows.sandbox = "unelevated"`; Linux/WSL without `bubblewrap` | Medium | Weaker or degraded enforcement |
| `history.persistence` absent/`"save-all"`; `cli_auth_credentials_store = "file"`; `log_dir` set; `otel.log_user_prompt = true` or third-party `otel.exporter`; `web_search = "live"` | Medium | Transcripts/tokens at rest; prompt data leaving; live injection surface |
| `allow_login_shell` not `false`; `--strict-config` unused in automation | Low | Login profiles sourced; typo'd hardening keys silently ignored |

Admin `requirements.toml`, and vendor-side account settings (not visible on the machine).

| Check | Severity | What it means |
|---|---|---|
| `allowed_approval_policies` includes `"never"`, `allowed_sandbox_modes` includes `danger-full-access`, or `allowed_permission_profiles` includes `":danger-full-access"` | High | The floor permits the Critical states |
| ChatGPT consumer sign-in (Free/Plus/Pro) with training on, or the Codex "train on full environments" toggle on | High | Repo contents train models; two separate switches |
| No `requirements.toml` on a managed fleet; no `[permissions.filesystem] deny_read`; `allow_managed_hooks_only` absent; no `[mcp_servers.<n>.identity]` allowlist | Medium | No enforceable floor; users self-downgrade, add hooks, run any MCP server |
| API-key org without ZDR where policy requires it | Medium | ZDR is org-level and needs OpenAI approval, not a CLI flag |
| `forced_login_method` / `forced_chatgpt_workspace_id` unset | Low | Users can sign in on a personal, training-eligible plan |

## Hardened baselines

### A. Preferred: permission-profile based, `~/.codex/config.toml` (Codex ≥ 0.138.0)

`sandbox_mode` and `[sandbox_workspace_write]` must appear in **no** loaded layer and `--sandbox` must never be passed, or all of this is inert. Top-level keys must precede every table.

```toml
approval_policy    = "on-request"   # or "untrusted" for maximum friction
approvals_reviewer = "user"         # "auto_review" adds a reviewer agent, not a boundary
allow_login_shell  = false
web_search = "cached"               # or "disabled"
default_permissions = "hardened"
cli_auth_credentials_store = "keyring"
[tools]
view_image = false                  # optional: drop the local image attachment tool
[permissions.hardened]
description = "Workspace-only writes; deny reads outside the workspace and to credential stores."
extends = ":workspace"              # keeps .git/.codex/.agents read-only inside roots
[permissions.hardened.filesystem]
":root"      = "deny"               # default-deny reads across the disk
":minimal"   = "read"               # toolchain paths Codex deems necessary
":tmpdir"    = "deny"
":slash_tmp" = "deny"
glob_scan_max_depth = 4             # required for unbounded ** deny globs
# Exact denies survive any future broadening of :minimal:
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
"."             = "write"
"**/*.env"      = "deny"
"**/.env*"      = "deny"
"**/*.pem"      = "deny"
"**/*.key"      = "deny"
"**/*.p12"      = "deny"
"**/id_rsa*"    = "deny"
"**/secrets/**" = "deny"
[permissions.hardened.network]
enabled = false                     # flip true only with [features] network_proxy = true,
                                    # which is REQUIRED for domain rules to be enforced;
                                    # then add [permissions.hardened.network.domains] entries.
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
[history]
persistence = "none"
[otel]
exporter = "none"
log_user_prompt = false
# Project trust: opt in, do not default in — [projects."/abs/path"] trust_level = "trusted"
```

### B. Legacy fallback: `sandbox_mode` (profiles unavailable, client < 0.138.0)

**This does not stop reads.** Under `read-only` and `workspace-write` the whole filesystem stays readable with no prompt. Only use it behind an outer boundary: devcontainer, VM, or a dedicated OS user with no access to the real dotfiles (reference: `openai/codex` `.devcontainer/`: `devcontainer.secure.json`, `Dockerfile.secure`, `init-firewall.sh`). Docs caveat: "If you run Codex with `--sandbox danger-full-access` … inside the container, a malicious project can exfiltrate anything available inside the devcontainer, including Codex credentials."

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

### C. Org floor: `/etc/codex/requirements.toml` · `%ProgramData%\OpenAI\Codex\requirements.toml`

```toml
allowed_approval_policies = ["untrusted", "on-request"]
default_permissions = "hardened"
allow_managed_hooks_only = true
[allowed_permission_profiles]
":read-only" = true
":workspace" = true
"hardened" = true
# ":danger-full-access" omitted => denied, including future profiles
[permissions.filesystem]
# absolute paths, or relative to $HOME/%USERPROFILE% with `~`; `./` is not allowed
deny_read = ["/**/*.env", "~/.ssh", "~/.aws", "~/.config/gcloud"]
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

### Hook example: official-derived (inline TOML form and JSON response are verbatim from the docs; the script path is composed)

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = '/usr/bin/python3 "$(git rev-parse --show-toplevel)/.codex/hooks/pre_tool_use_policy.py"'
timeout = 30
statusMessage = "Checking Bash command"
```

The hook blocks the call by writing to stdout: `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "Destructive command blocked by hook."}}`. Legacy `{"decision":"block","reason":"…"}` and exit code `2` + stderr also work. Events: `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `UserPromptSubmit`, `Stop`.

**Repo-committable keys:** everything in A and B *can* live in `<repo>/.codex/config.toml` except `notify`, `otel`, `profile`/`profiles` and the provider/base-URL keys, but it applies only once the project is trusted, and it is the same layer a hostile repo uses to *loosen* config. Prefer user-level (A) or admin-level (C). A repo may reasonably commit tightening-only `[permissions.<n>.filesystem.":workspace_roots"]` denies plus an `AGENTS.md` note; treat any repo-committed `sandbox_mode`, `approval_policy`, `[hooks]` or `[mcp_servers]` as a finding regardless of value.

## Verify at runtime

```bash
codex --version                        # need >= 0.138.0 for permission profiles
codex --strict-config                  # errors on unrecognized keys — catches typo'd hardening
codex sandbox macos  --permissions-profile hardened --log-denials -- cat "$HOME/.ssh/id_rsa"
codex sandbox linux  --permissions-profile hardened -- cat "$HOME/.ssh/id_rsa"
codex sandbox windows --permissions-profile hardened -- cmd /c type "%USERPROFILE%\.ssh\id_rsa"
codex execpolicy check --pretty --rules ~/.codex/rules/default.rules -- curl https://example.com
```

`codex sandbox` aliases: `codex debug`, `codex sandbox seatbelt`, `codex sandbox landlock`. In-session: `/status` (workspace roots, effective sandbox), `/permissions` (active profile), `/hooks` (hook trust).

**Profile active vs. overridden:** `grep -rn 'sandbox_mode\|sandbox_workspace_write' ~/.codex /etc/codex <repo>/.codex` must return nothing and no wrapper may pass `--sandbox`; if `/permissions` reports a sandbox mode instead of your profile name, some layer has overridden it. Empirically, the `cat` probes above must be denied; a successful read of `~/.ssh/id_rsa` means legacy sandbox semantics are in force and the profile is inert.

## Sources

- Config: <https://learn.chatgpt.com/docs/config-file/config-basic> · <https://learn.chatgpt.com/docs/config-file/config-advanced> · <https://learn.chatgpt.com/docs/config-file/config-reference> · <https://learn.chatgpt.com/docs/config-file/config-sample> · <https://learn.chatgpt.com/docs/config-file/environment-variables>
- Sandbox & approvals: <https://learn.chatgpt.com/docs/agent-approvals-security> · <https://learn.chatgpt.com/docs/sandboxing> · <https://learn.chatgpt.com/docs/sandboxing/auto-review> · <https://learn.chatgpt.com/docs/permissions>
- Extension points: <https://learn.chatgpt.com/docs/hooks> · <https://learn.chatgpt.com/docs/agent-configuration/rules> · <https://learn.chatgpt.com/docs/agent-configuration/agents-md> · <https://learn.chatgpt.com/docs/extend/mcp>
- Enterprise & auth: <https://learn.chatgpt.com/docs/auth> · <https://learn.chatgpt.com/docs/enterprise/managed-configuration> · <https://learn.chatgpt.com/docs/cyber-safety/recommended-configuration> · <https://learn.chatgpt.com/docs/enterprise/chatgpt-work-local-security>
- Data/training: <https://developers.openai.com/api/docs/guides/your-data> · <https://help.openai.com/en/articles/5722486-how-your-data-is-used-to-improve-model-performance> · <https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan>
- Source evidence: <https://github.com/openai/codex/blob/main/codex-rs/protocol/src/permissions.rs> · <https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt.rs> · <https://github.com/openai/codex/blob/main/codex-rs/core/src/context/world_state/environment.rs> · <https://github.com/openai/codex/tree/main/.devcontainer>
- Docs index (machine-readable, every page has a `<url>.md` twin): <https://learn.chatgpt.com/llms.txt>
