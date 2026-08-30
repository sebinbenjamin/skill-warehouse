# Claude Code: hardening reference

Verified against: `code.claude.com/docs` as of 2026-08-30; latest CLI in changelog `2.1.251` (2026-08-28). Version-gated behaviours below name the minimum version. Anything not confirmed against a primary source is marked `[UNVERIFIED]`.

## Config surfaces

| File | Scope | Committed to repo? | Precedence / trust notes |
| :-- | :-- | :-- | :-- |
| `managed-settings.json` + `managed-settings.d/*.json` | Managed | N/A | Highest. Drop-ins merge after the base file in alphabetical order. macOS `/Library/Application Support/ClaudeCode/managed-settings.json`; Linux/WSL `/etc/claude-code/managed-settings.json`; Windows `C:\Program Files\ClaudeCode\managed-settings.json` (legacy `C:\ProgramData\ClaudeCode\` is **not** read). macOS profile domain `com.anthropic.claudecode`. |
| CLI args (`--settings`, `--allowedTools`, …) | Session | N/A | Below managed, above local. `--settings <file>` anchors `/path` rules at that file's directory. |
| `.claude/settings.local.json` | Project local | No | Auto-added to your **global** git excludes only when Claude Code creates it; a hand-made file is ignored by nobody. `/path` anchors at the primary working directory. |
| `.claude/settings.json` | Project shared | **Yes** | The only local lever cloud sessions read. `/path` anchors at the primary working directory. |
| `~/.claude/settings.json` | User | No | Lowest non-default. **`/path` anchors at `~/.claude/path`.** `%USERPROFILE%\.claude` on Windows; `CLAUDE_CONFIG_DIR` relocates it. |
| `.mcp.json` (repo root) | Project | Yes | Servers connect **without asking** in `claude -p`/SDK regardless of approval state. |
| `CLAUDE.md`, `.claude/rules/`, `.claude/{skills,agents,commands,hooks,workflows}/`, `scheduled_tasks.json` | Project | Yes | Executable/config content the repo ships to you. |

Cross-cutting rules:

- **Lists merge, they do not override.** The same key in multiple files (e.g. `permissions.allow`) concatenates.
- **Deny wins across every scope and every mode**, including `bypassPermissions`. A user-level deny blocks a project-level allow.
- **Workspace trust:** a repo's `permissions.allow` and `permissions.additionalDirectories` apply only after the trust dialog. `deny` and `ask` apply immediately. **Hooks, the `env` block, `apiKeyHelper`, skills' `allowed-tools`, and `.mcp.json` servers run before/without trust**, including when only a *parent* folder was trusted.
- **`claude -p` and the Agent SDK never show the trust dialog** and count as accepted. Containment flags: `--setting-sources user`, `--bare`, `--settings '{"disableAllHooks": true}'` (user-scope `disableAllHooks` alone is outranked by project settings), `disabledMcpjsonServers`, `--strict-mcp-config`, `--restricted`.
- **Cloud sessions** read `.claude/settings.json` and server-managed settings only, not `~/.claude/settings.json`, not `.claude/settings.local.json`, not a local `managed-settings.json`/MDM profile. They also ignore `bypassPermissions` and `dontAsk` from settings files.
- **VS Code extension** ignores project settings for the starting permission mode (uses `claudeCode.initialPermissionMode` → last mode picked → managed/user `defaultMode`).
- **Keys ignored from project/local scope:** `sandbox.filesystem.disabled`, `sandbox.network.strictAllowlist`, `sandbox.allowAppleEvents`, credential `mask`/`tlsTerminate`/`allowPlaintextInject`/`awsPairs`/`sigv4`, `defaultMode: "auto"`, and env vars `CLAUDE_CODE_PROCESS_WRAPPER`, `CLAUDE_CODE_SYNC_SKILLS`, `CLAUDE_CODE_SYNC_PLUGINS`, `CLAUDE_CODE_PLUGIN_CACHE_DIR`, `CLAUDE_CODE_PLUGIN_SEED_DIR`, and (2.1.251+) `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_TMPDIR`, `TMPDIR`/`TMP`/`TEMP`. `CLAUDE_CODE_RESTRICTED` is ignored from every `env` block.

## What each control actually stops

Tiers: **T1** OS sandbox · **T2** egress allowlist · **T3** credential scrub · **T4** harness deny rule · **T5** hook · **T6** ignore file · **T7** instruction file.

| Control | Tier | Stops | Does NOT stop |
| :-- | :-- | :-- | :-- |
| `permissions.deny` `Read(path)` | T4 | Read tool; Grep/Glob (best-effort, incl. exclusion from search results); `@file` mentions; IDE selection context; Edit (2.1.208+); Write incl. file creation (2.1.228+); Bash `cat`/`head`/`tail`/`sed` | Arbitrary subprocesses (`python -c`, `node -e`, Makefile targets, dotenv in tests); NotebookEdit; MCP file tools |
| `permissions.deny` `Edit(path)` | T4 | Edit/Write/NotebookEdit at that path; output redirections `>`, `>>`, `2>` | Subprocess writes; MCP writes |
| `permissions.deny` `Bash(cmd *)` | T4 | The named binary as a parsed subcommand, matched past leading env assignments (`FOO=b rm -rf` is caught) | Argument-level constraints; unstripped runners (`npx`, `docker exec`, `devbox run`, `mise exec`, `direnv exec`); the binary invoked from inside a script |
| `permissions.deny` bare `Bash` / `WebSearch` / `mcp__*` | T4 | Removes the tool from Claude's context entirely | MCP *servers* still launch and load (use `deniedMcpServers`/`allowedMcpServers`/`--strict-mcp-config`) |
| `permissions.deny` `WebFetch(domain:*)` | T4 + T2 | Every in-process fetch, **and** sets the sandbox denied-domain list to everything | `curl`/`wget`/any Bash egress. A **bare** `WebFetch` rule does not touch sandbox domain lists at all |
| `permissions.ask` | T4 | Silent execution; a hook-issued `"ask"` forces a prompt even in auto mode | `bypassPermissions`; unattended `-p` sessions; a bare `Bash` ask rule is skipped for sandboxed commands (except plan mode, 2.1.212+) |
| Permission modes (`default`/`plan`/`acceptEdits`/`auto`/`dontAsk`/`bypassPermissions`) | T4 (policy) | Baseline of what runs unprompted | Not a boundary. Deny rules, protected paths and critical-path `rm` checks survive every mode; `auto` is a classifier model, not enforcement |
| `sandbox.filesystem` (`denyRead`/`allowWrite`) | T1 | Bash **and all child processes**, including arbitrary subprocesses, the only layer that does | Read/Edit/Write tools, WebFetch/WebSearch, MCP servers, hooks, computer use. **Not available on native Windows.** Fails **open** (warn + run unsandboxed) unless `failIfUnavailable: true` |
| `sandbox.network` (`allowedDomains`/`strictAllowlist`) | T2 | Sandboxed Bash egress, by client-supplied hostname | In-process WebFetch/WebSearch, MCP, hooks. No TLS inspection → domain fronting. Broad hosts (`github.com`) are themselves exfil channels (gists, PR bodies, issue comments) |
| `sandbox.credentials.files` `"mode":"deny"` | T1/T3 | Sandboxed reads of the listed files (a `denyRead` inside the sandbox) | Anything not listed: **there is no built-in credential deny list**. Lifted by `filesystem.disabled` (except a macOS file `mask`, which holds) |
| `sandbox.credentials.envVars` `"mode":"deny"` | T3 | Unsets the named var before each sandboxed command; independent of the filesystem layer | Vars not listed; non-Bash surfaces. `deny` entries merge from every scope and no scope can remove one |
| `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` | T3 | Strips Anthropic + cloud-provider credentials from **all** subprocess environments (Bash tool, hooks, MCP stdio) regardless of sandboxing; on Linux also runs Bash in an isolated PID namespace | Your own app secrets. Side effects: forces `autoAllowBashIfSandboxed` off, makes `filesystem.disabled` ignored from every source, blinds `ps`/`pgrep`/`kill` to host processes |
| Hooks (`PreToolUse`) | T5 | `exit 2` or `permissionDecision: "deny"` blocks **before** permission rules, in every mode incl. `bypassPermissions`/`--dangerously-skip-permissions` | Fails open on bad path (exit ~127), exit 1, timeout (`command`/`http`/`mcp_tool`), non-2xx or non-JSON HTTP. A hook `"allow"` cannot override deny/ask rules |
| `--restricted` (2.1.248+) | T4 | Removes command/code-running tools **and WebFetch** unless named in `--tools`; confines file tools to working dirs; loads **only** managed + `--settings`; refuses `bypassPermissions` and cloud sessions; classifier can't approve protected-path writes | Not an OS boundary; must be passed per invocation (`CLAUDE_CODE_RESTRICTED=1` works but is ignored from a settings `env` block) |
| Managed locks (`allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `filesystem.allowManagedReadPathsOnly`, `network.allowManagedDomainsOnly`) | T4 | Make policy non-bypassable by the developer or the repo | `sandbox.excludedCommands` has **no** managed lock: any developer can append entries that run outside the sandbox |
| `CLAUDE.md`, `.claude/rules/` | T7 | Shapes what Claude attempts; the auto-mode classifier reads it | Nothing. Delivered as a user message after the system prompt; no compliance guarantee |
| `.gitignore` entry for `settings.local.json`; `claudeMdExcludes` | T6 | Leaking personal rules into the repo; loading vendored CLAUDE.md | Any tool access. `claudeMdExcludes` does not apply to managed-policy CLAUDE.md |

## Rule semantics you must get right

1. **Evaluation order is deny → ask → allow, first match wins; specificity is irrelevant.** A broad `Bash(aws *)` deny beats a narrow `Bash(aws s3 ls)` allow; a deny rule cannot carry allowlist exceptions.
2. **A bare tool name in `deny` removes the tool from context** (`"Bash"`, `"WebSearch"`, `"mcp__*"`). A scoped rule leaves the tool present and blocks matching calls. `EndConversation` cannot be removed while any other tool remains.
3. **Four path anchors for `Read`/`Edit` (gitignore pattern syntax):** `//path` = filesystem root; `~/path` = home; `/path` = **relative to the settings source**; `path` or `./path` = cwd. `Read(/Users/alice/file)` is *not* absolute.
4. **User-settings trap:** `/path` in `~/.claude/settings.json` resolves to `~/.claude/path`, not `~/path`, not the project. Rules meant to apply inside every project must use `//` or `~/`.
5. **Windows paths normalise to POSIX before matching:** `C:\Users\alice` → `/c/Users/alice`. Use `//c/**/.env` for one drive, `//**/.env` across all drives.
6. **Depth semantics differ by rule type.** Bare filenames match at any depth (`Read(.env)` ≡ `Read(**/.env)`). A single-segment `src/**` matches only `<cwd>/src` in **allow**, but a `src` directory at **any depth** in **deny/ask**. Every other shape (`/src/**`, `**/src/**`) is depth-consistent. `Read(.env)` does not cover a parent directory or another project; `Read(//**/.env)` does.
7. **Symlinks are checked as both path and resolved target:** allow requires both to match, deny fires if either does. Two symlink bypasses (file tools following a symlink swapped after the permission check; Grep/Glob not applying `Read` denies through a symlinked search path) were fixed only in **2.1.251**; treat earlier versions as unsound.
8. **`Read` deny coverage:** yes for Read, Grep, Glob, `@file`, IDE context, Edit (2.1.208+), Write (2.1.228+), Bash `cat`/`head`/`tail`/`sed`. **No** for NotebookEdit (add an `Edit(...)` deny), arbitrary subprocesses, MCP tools.
9. **Inert rule shapes**, accepted with a startup warning, never consulted: `Write(<path>)`, `Glob(<path>)`, `MultiEdit(<path>)`, `NotebookEdit(<path>)` (use `Edit(...)`/`Read(...)` instead), primary-content parameter rules (`Bash(command:…)`, `Read(file_path:…)`, `WebFetch(url:…)`, `Grep(path:…)`), `mcp__server(...)` with parentheses in a settings file (only `--disallowedTools` accepts those), and tool-name globs in `allow` (`"*"`, `"B*"`, `"mcp__*"`; only `mcp__<literal-server>__<glob>` is valid there). A bare tool-name deny with no path is fine.
10. **Bash compound splitting:** separators `&&`, `||`, `;`, `|`, `|&`, `&`, newline. Every subcommand must match independently, so `Bash(safe-cmd *)` does not authorise `safe-cmd && other-cmd`.
11. **Wrappers stripped before matching:** `timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`, flagless `xargs`. Leading known-safe env assignments are stripped for allow rules; deny/ask match past them.
12. **Runners NOT stripped and not configurable:** `direnv exec`, `devbox run`, `mise exec`, `npx`, `docker exec`, so `Bash(devbox run *)` in **allow** authorises `devbox run rm -rf .`. `watch`, `setsid`, `ionice`, `flock`, and `find` with `-exec`/`-delete` can never be prefix-approved.
13. **The read-only command set never prompts, in any mode, and is not configurable:** `ls cat echo pwd head tail grep find wc which diff stat du cd` plus read-only `git`. `cat ~/.aws/credentials` is stopped by the `Read` deny rule alone; a missing or mis-anchored rule means it simply runs. Commands over 10,000 characters, or that Claude Code cannot parse, always prompt.
14. **`WebFetch(domain:x)`** is exact host, case-insensitive, trailing dot stripped; `*.example.com` matches subdomains at any depth but **not** `example.com`; a wildcard anywhere other than a leading `*.` matches only the text between two dots. Wildcards need 2.1.172+. Only the `domain:` form feeds the sandbox host lists; a bare `WebFetch` rule does not.
15. **PowerShell rules** canonicalise aliases (a `Get-ChildItem` rule also matches `gci`/`ls`/`dir`), match case-insensitively, and split on `|`, `;`, and PS7 `&&`/`||`; every subcommand must match.
16. **Hooks block only on exit 2** (or a valid `permissionDecision: "deny"`). Exit 1 is a *non-blocking* error and the action proceeds. Multiple PreToolUse hooks resolve `deny > defer > ask > allow`. Matchers that are not plain word lists are **unanchored JS regexes**: `Edit.*` also matches `NotebookEdit`; MCP needs `mcp__server__.*`, a bare `mcp__server` matches nothing.
17. **`defaultMode: "auto"` is ignored from project/local settings**, and when a project file sets it, the user-settings `defaultMode` is ignored too and the built-in default applies. **The built-in default is `auto` on Pro/Max/Team** in terminal/VS Code (2.1.228+ macOS/Linux/WSL, 2.1.233+ native Windows). It is `default` for `-p`/SDK, Enterprise, Console API keys, Bedrock/Google Agent Platform/Foundry/AWS gateways, any file setting `disableAutoMode`, and when feature-flag fetching is off. **No `defaultMode` present ≠ manual mode.**
18. **The sandbox does not exist on native Windows** (Seatbelt/bubblewrap only; WSL1 unsupported) and **fails open** unless `failIfUnavailable: true`. Linux/WSL2 needs `bubblewrap` + `socat`; Unix-socket blocking additionally needs the `@anthropic-ai/sandbox-runtime` seccomp filter; Ubuntu 24.04+ needs an AppArmor profile for `bwrap`.
19. **Sandbox path prefixes differ from permission-rule anchoring:** `/tmp/build` is absolute, `~/.kube` is home-relative, `./output` or bare `output` is project-root-relative in project settings but `~/.claude`-relative in user settings. Overlap resolves to the more specific path, and a narrow `denyRead` holds inside a wider `allowRead`.
20. **Sandbox default read policy is the entire computer**: `~/.aws/credentials` and `~/.ssh/` included. **There is no built-in credential deny list**; only what you enumerate is restricted. Default writes are cwd + `--add-dir` dirs + `$TMPDIR`; default network is no domains pre-allowed.
21. **Honoured only from user/managed/`--settings`:** `sandbox.filesystem.disabled`, `network.strictAllowlist`, credential `mask`, `network.tlsTerminate`, `allowPlaintextInject`, `awsPairs`, `sigv4`, `allowAppleEvents`. Setting any of them in a repo file is silently inert (by design: a checked-out project cannot switch filesystem isolation off).
22. **Protected paths are never auto-approved for writes** in any mode but bypass, and `permissions.allow` cannot pre-approve them (`.git`, `.claude` except `worktrees`, `.vscode`, `.idea`, `.husky`, `.devcontainer`, the shell rc family, `.npmrc`, `.mcp.json`, `.claude.json`, hook/CI config files, …). **Critical-path `rm`/`rmdir`** (filesystem root, top-level dirs, home, drive root, cwd or its parents) cannot be approved by any allow rule or hook `"allow"`.
23. **`autoAllowBashIfSandboxed` defaults to `true`**: sandboxed commands run with no prompt even in Manual mode. `allowUnsandboxedCommands` defaults to `true`, so a blocked command may be retried unsandboxed through the normal permission flow; set it `false` (Strict sandbox mode), or add an ask rule for `Bash(dangerouslyDisableSandbox:true)`.
24. **`/cd <path>` (2.1.246+) moves the primary working directory and applies the new directory's project settings, hooks, `.mcp.json` servers, plugins, skills, subagents and `env` values**: an escape from a hardened repo config into a sibling repo's. `Cd` rules gate only the human's `/cd` (not model-invocable): a bare `Cd` deny disables it; any `Cd` allow rule switches it to allowlist mode (`Cd(~/code/**)`). Neither baseline below includes one; add it for multi-repo machines.

## Detection checklist

Severity is the severity of the finding when the check fires as described.

### Repo `.claude/` and `.mcp.json`

| Check | Severity | What it means |
| :-- | :-- | :-- |
| `--dangerously-skip-permissions` / `--permission-mode bypassPermissions` in scripts, npm scripts, shell aliases, CI workflows, devcontainer commands | Critical | Every allow-side control is off for those runs; only deny rules and hooks survive |
| `permissions.defaultMode: "bypassPermissions"` | Critical | The same, persistently |
| `permissions.allow` contains `Bash`, `Bash(*)`, `Bash(python*)`, `Bash(sh *)`, `Bash(npx *)`, `Bash(docker *)`, `Bash(devbox run *)`, `Bash(direnv exec *)` | Critical | Arbitrary code execution; those runners are not stripped before matching |
| `permissions.allow` contains `Read(~/…)`, `Read(//…)`, or any path outside the repo | Critical | Out-of-repo read grant (trust-gated, but granted once trusted) |
| `WebFetch(domain:*)` in `allow` | Critical | Fetches anywhere **and** opens the sandbox host list to every domain |
| `enableAllProjectMcpServers: true` | Critical | Auto-approves every `.mcp.json` server with no prompt; MCP tools bypass `Read`/`Edit` denies entirely |
| `sandbox.network.allowedDomains` contains `*` or a bare wildcard | Critical | No egress boundary |
| `sandbox.network.allowAllUnixSockets: true`, or `allowUnixSockets` containing `docker.sock` | Critical | Sandbox escape to the host daemon |
| `.claude/settings.local.json` tracked in git | Critical | Personal allow rules shipped to every clone, and they outrank the shared file |
| Hook scripts blocking with `exit 1` instead of `exit 2` | Critical | The gate is a no-op; the action proceeds |
| Hook `command` path missing, mistyped, or non-executable | Critical | Exit ~127 is a non-blocking error; a silently disabled gate |
| `sandbox.enabled: true` presented as the boundary on a native-Windows host | Critical | The entire `sandbox` block is inert; permission rules and hooks are the whole boundary |
| `permissions.defaultMode: "acceptEdits"` | High | Edits plus `mkdir touch rm rmdir mv cp sed` run unprompted inside the working dirs |
| `permissions.additionalDirectories` non-empty | High | Persistent out-of-repo file access; trust-gated. (`--add-dir` is a bigger grant: it also loads that directory's skills/commands/agents/plugins) |
| No `permissions.deny` for `.env`, key material, `~/.ssh`, `~/.aws` | High | Nothing stops the built-in Read tool or `cat` |
| Mis-anchored deny rules: `Read(/Users/…)`, `Read(/home/…)`, `Read(/etc/…)` | High | A single leading slash anchors at the settings source, so the rule matches nothing real |
| `sandbox.excludedCommands` non-empty | High | Each entry runs entirely outside the sandbox; no managed lock exists for this key |
| `sandbox.enableWeakerNestedSandbox` / `enableWeakerNetworkIsolation` / `allowAppleEvents: true` | High | Documented as considerably weakening or removing code-execution isolation (`allowAppleEvents` is inert from project scope) |
| `.claude/` ships `hooks/`, `agents/`, `commands/`, `skills/`, `workflows/`, `scheduled_tasks.json`, or an `env` block | High | All of it runs in `claude -p` before any trust dialog; review each file |
| Inert rules present: `Write(<path>)`, `Glob(<path>)`, `MultiEdit(<path>)`, `NotebookEdit(<path>)`, `mcp__server(...)` | Medium | False sense of security: accepted, warned about at startup, never consulted |
| `Read(...)` deny with no matching `Edit(...)` deny | Medium | NotebookEdit can still write the path |
| Bash rules constraining arguments (`Bash(curl https://x/ *)`) | Medium | Structurally unreliable: flag order, protocol, redirects, `URL=… && curl $URL`, extra whitespace |
| No `Bash(curl:*)`/`Bash(wget:*)` deny and no egress hook | Medium | WebFetch rules do not restrict Bash network access |
| `.mcp.json` present with no `disabledMcpjsonServers`/`allowedMcpServers`/`deniedMcpServers` | Medium | Servers connect unasked in `-p`/SDK sessions |
| `.gitignore` lacks `.claude/settings.local.json` | Medium | Auto-ignore only happens on the machine that created the file, and it writes to global excludes, not the repo |
| `permissions.defaultMode: "auto"` in a project file | Medium | Silently ignored **and** it suppresses the user-settings `defaultMode` |
| PreToolUse hooks relying on `timeout` to gate | Medium | A timed-out `command`/`http`/`mcp_tool` hook does not block |
| `CLAUDE.md` / `.claude/rules/` with `@` imports resolving outside the repo | Medium | An approval dialog appears interactively only; review the targets |
| `permissions.disableBypassPermissionsMode: "disable"` present | Info | Good: rejects the flag and a subagent's `permissionMode: bypassPermissions` (2.1.223+) |
| `sandbox.enabled: true`, `allowUnsandboxedCommands: false`, `filesystem.denyRead` covering `~/.ssh`/`~/.aws`/`~/.claude`, `credentials.files`/`.envVars` deny entries | Info | Good: the T1/T3 layers are configured |
| `sandbox.autoAllowBashIfSandboxed` unset | Info | Defaults to `true`: sandboxed commands never prompt |
| `sandbox.filesystem.disabled: true` in a project file | Info | Ignored from project scope by design |
| `includeGitInstructions: false`, `attribution.*`, `cleanupPeriodDays` | Info | Disclosure and retention preferences |

### User `~/.claude/`

| Check | Severity | What it means |
| :-- | :-- | :-- |
| Shell aliases or wrapper scripts injecting `--dangerously-skip-permissions` | Critical | Machine-wide bypass regardless of repo config |
| Deny rules written as bare `/path` | Critical | They anchor at `~/.claude/path`; the intended paths are unprotected |
| `~/.claude/projects/**` or `~/.claude/history.jsonl` group/world-readable | Critical | Plaintext transcripts; any secret a tool ever read is on disk. `history.jsonl` (every prompt, with timestamp and project path) is **never** swept by the retention sweep |
| No `permissions.deny` for `~/.ssh/**`, `~/.aws/**`, `~/.claude/.credentials.json`, `~/.claude.json` | High | Nothing stops cross-project credential reads |
| `permissions.defaultMode` absent | High | The built-in default is `auto` on Pro/Max/Team, not manual |
| `skipDangerousModePermissionPrompt: true` | Medium | The bypass-mode warning dialog has already been accepted |
| `sandbox.enabled` / `network.strictAllowlist` / `sandbox.credentials.*` absent | Medium | These are honoured only from user/managed/`--settings`; no other scope can supply them |
| `cleanupPeriodDays` at its default of 30; `desktopSessionCleanupPeriodDays` unset | Medium | Desktop/Cowork transcripts otherwise have **no** age limit (the key needs 2.1.248+) |
| `env` lacks `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`, `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING` | Low | Subprocesses inherit provider credentials; non-essential traffic stays on |
| `~/.claude.json` `projects["<path>"].hasTrustDialogAccepted` | Info | Which folders are trusted; a trusted parent covers nested repos |

### System / managed

| Check | Severity | What it means |
| :-- | :-- | :-- |
| Windows hosts in scope while the policy relies on `sandbox` | Critical | The block does nothing there; those users need WSL2 or a container |
| No `managed-settings.json` at the OS path and no `managed-settings.d/*.json` | High | Nothing in the setup is non-bypassable by the developer or the repo |
| `requiredMinimumVersion` absent or `< 2.1.251` | High | Missing the symlink-swap and Grep/Glob-through-symlink deny-rule fixes |
| `sandbox.failIfUnavailable` unset or false on a macOS/Linux/WSL2 fleet | High | Sandbox failure degrades silently to unsandboxed execution |
| `allowManagedPermissionRulesOnly: true` with an incomplete managed deny list | High | It discards user/project/local **deny** rules too, plus `--allowedTools`, hides "always allow", and stops saving new rules: the managed list becomes the entire policy |
| `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `filesystem.allowManagedReadPathsOnly`, `network.allowManagedDomainsOnly` present | Info | Good, with the same completeness caveat |
| `permissions.disableBypassPermissionsMode` + `disableAutoMode` | Info | Good: removes both escape hatches |
| `strictKnownMarketplaces: []`, `disableSkillShellExecution: true` | Info | Good: no plugin marketplaces, no inline shell in skills/commands |

## Hardened baselines

### A. Repo: `.claude/settings.json` (committed)

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "permissions": {
    "defaultMode": "default",
    "disableBypassPermissionsMode": "disable",
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(**/.env)",
      "Read(**/.env.*)",
      "Read(**/*.pem)",
      "Read(**/*.key)",
      "Read(**/*.p12)",
      "Read(**/*.pfx)",
      "Read(**/id_rsa*)",
      "Read(**/id_ed25519*)",
      "Read(**/secrets/**)",
      "Read(**/.secrets/**)",
      "Read(**/credentials)",
      "Read(**/credentials.json)",
      "Read(**/*.tfstate)",
      "Read(**/*.tfstate.*)",
      "Read(**/.npmrc)",
      "Read(**/.pypirc)",
      "Read(**/.netrc)",
      "Read(**/.git-credentials)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(~/.gnupg/**)",
      "Read(~/.kube/**)",
      "Read(~/.docker/config.json)",
      "Read(~/.config/gcloud/**)",
      "Read(~/.azure/**)",
      "Read(~/.netrc)",
      "Read(~/.git-credentials)",
      "Read(~/.npmrc)",
      "Read(~/.claude/.credentials.json)",
      "Read(~/.claude.json)",
      "Read(~/.claude/history.jsonl)",
      "Read(~/.claude/projects/**)",
      "Read(~/.bash_history)",
      "Read(~/.zsh_history)",
      "Edit(**/.env)",
      "Edit(**/.env.*)",
      "Edit(**/secrets/**)",
      "Edit(~/.ssh/**)",
      "Edit(~/.aws/**)",
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(nc:*)",
      "Bash(ncat:*)",
      "Bash(netcat:*)",
      "Bash(telnet:*)",
      "Bash(scp:*)",
      "Bash(sftp:*)",
      "Bash(ssh:*)",
      "Bash(rsync:*)",
      "Bash(env)",
      "Bash(printenv:*)",
      "Bash(aws configure *)",
      "Bash(git config --global *)",
      "WebFetch(domain:*)",
      "WebSearch"
    ],
    "ask": [
      "Bash(git push *)",
      "Bash(git remote *)",
      "Bash(gh *)",
      "Bash(npm publish *)",
      "Bash(docker *)",
      "Bash(kubectl *)",
      "Bash(terraform *)",
      "Bash(dangerouslyDisableSandbox:true)"
    ]
  },
  "sandbox": {
    "enabled": true,
    "autoAllowBashIfSandboxed": false,
    "allowUnsandboxedCommands": false,
    "excludedCommands": [],
    "filesystem": {
      "denyRead": [
        "~/.ssh",
        "~/.aws",
        "~/.gnupg",
        "~/.kube",
        "~/.config/gcloud",
        "~/.azure",
        "~/.netrc",
        "~/.git-credentials",
        "~/.npmrc",
        "~/.claude",
        "~/.claude.json",
        "~/.bash_history",
        "~/.zsh_history"
      ]
    },
    "credentials": {
      "files": [
        { "path": "~/.ssh", "mode": "deny" },
        { "path": "~/.aws/credentials", "mode": "deny" },
        { "path": "~/.git-credentials", "mode": "deny" },
        { "path": "~/.npmrc", "mode": "deny" }
      ],
      "envVars": [
        { "name": "GITHUB_TOKEN", "mode": "deny" },
        { "name": "GH_TOKEN", "mode": "deny" },
        { "name": "NPM_TOKEN", "mode": "deny" },
        { "name": "AWS_ACCESS_KEY_ID", "mode": "deny" },
        { "name": "AWS_SECRET_ACCESS_KEY", "mode": "deny" },
        { "name": "AWS_SESSION_TOKEN", "mode": "deny" },
        { "name": "ANTHROPIC_API_KEY", "mode": "deny" },
        { "name": "OPENAI_API_KEY", "mode": "deny" }
      ]
    },
    "network": {
      "allowedDomains": ["registry.npmjs.org"],
      "allowAllUnixSockets": false,
      "allowUnixSockets": [],
      "allowLocalBinding": false
    }
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Grep|Glob|Edit|Write|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/deny-secrets.sh",
            "timeout": 10
          }
        ]
      },
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/block-egress.sh",
            "timeout": 10
          }
        ]
      }
    ]
  },
  "enableAllProjectMcpServers": false,
  "disableClaudeAiConnectors": true,
  "includeGitInstructions": false,
  "attribution": { "commit": "", "pr": "", "sessionUrl": false },
  "cleanupPeriodDays": 7
}
```

Trade-offs to state when proposing this file:

- It contains no `allow` rules and no `additionalDirectories`: both are trust-gated from project scope, so a committed file cannot rely on them. `deny` and `ask` apply immediately, trusted or not.
- `WebFetch(domain:*)` in deny refuses every fetch **and** empties the sandbox allowed-host list. If Claude needs to read docs, drop it and allow specific `WebFetch(domain:…)` hosts instead; a bare `WebFetch` allow rule does not widen the sandbox host list.
- `Bash(env)` and `Bash(printenv:*)` are `[UNVERIFIED as effective]`: valid deny syntax, no documented example, and neither can stop `echo $TOKEN`.
- `autoAllowBashIfSandboxed: false` costs prompts. Setting it `true` is the documented low-friction posture and still leaves deny rules, content-scoped ask rules, and critical-path `rm` checks in force.
- On native Windows the whole `sandbox` block is inert; run under WSL2 or a container, or treat this file as permission-rules-only.
- This file cannot stop reads of a *sibling* repo checkout. The `~/…` rules are home-anchored and work; a neighbouring project directory is not covered. Use `sandbox.filesystem.denyRead` or `--restricted` for that.

### B. User: `~/.claude/settings.json`

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "permissions": {
    "defaultMode": "default",
    "disableBypassPermissionsMode": "disable",
    "deny": [
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(~/.gnupg/**)",
      "Read(~/.kube/**)",
      "Read(~/.config/gcloud/**)",
      "Read(~/.azure/**)",
      "Read(~/.netrc)",
      "Read(~/.git-credentials)",
      "Read(~/.npmrc)",
      "Read(~/.pypirc)",
      "Read(~/.bash_history)",
      "Read(~/.zsh_history)",
      "Read(~/.claude/.credentials.json)",
      "Read(~/.claude.json)",
      "Read(~/.claude/history.jsonl)",
      "Read(~/.claude/projects/**)",
      "Read(//**/.env)",
      "Read(//**/.env.*)",
      "Read(//**/id_rsa*)",
      "Read(//**/id_ed25519*)",
      "Read(//**/*.pem)",
      "Read(//**/.git-credentials)",
      "Edit(~/.ssh/**)",
      "Edit(~/.aws/**)",
      "Edit(//**/.env)"
    ],
    "ask": [
      "Bash(git push *)",
      "Bash(gh *)",
      "Bash(dangerouslyDisableSandbox:true)"
    ]
  },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": false,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyRead": ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.azure", "~/.config/gcloud", "~/.claude", "~/.claude.json"]
    },
    "credentials": {
      "files": [
        { "path": "~/.ssh", "mode": "deny" },
        { "path": "~/.aws/credentials", "mode": "deny" }
      ],
      "envVars": [
        { "name": "GITHUB_TOKEN", "mode": "deny" },
        { "name": "GH_TOKEN", "mode": "deny" },
        { "name": "NPM_TOKEN", "mode": "deny" },
        { "name": "AWS_ACCESS_KEY_ID", "mode": "deny" },
        { "name": "AWS_SECRET_ACCESS_KEY", "mode": "deny" }
      ]
    },
    "network": {
      "strictAllowlist": true,
      "allowedDomains": ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "*.github.com"],
      "allowAllUnixSockets": false,
      "allowLocalBinding": false
    }
  },
  "env": {
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_FEEDBACK_COMMAND": "1",
    "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1"
  },
  "disableClaudeAiConnectors": true,
  "includeGitInstructions": false,
  "cleanupPeriodDays": 7,
  "desktopSessionCleanupPeriodDays": 7,
  "feedbackDrafts": "off",
  "skipWebFetchPreflight": false
}
```

Trade-offs: `strictAllowlist` and credential `mask` are honoured only from user/managed/`--settings`, which is why they live here rather than in a repo file. `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` forces `autoAllowBashIfSandboxed` off, makes `filesystem.disabled` ignored from every source (good), and hides host processes from `ps`/`pgrep`/`kill` on Linux. `failIfUnavailable` is `false` only because on native Windows the sandbox never starts and `true` would refuse to launch; set it `true` on macOS/Linux/WSL2 fleets. `skipWebFetchPreflight` stays `false` so fetches keep hitting Anthropic's malicious-host blocklist (the preflight sends the hostname only, not the URL or content); set `true` only in egress-restricted environments. Adding `"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"` also disables auto-updates and feature-flag fetching, which forces the built-in starting mode back to `default`. Note that these traffic switches disable traffic even when set to `"0"` or `"false"`; unset them to re-enable.

### C. Managed: `managed-settings.json`

```json
{
  "permissions": {
    "defaultMode": "default",
    "disableBypassPermissionsMode": "disable",
    "deny": [
      "Read(//**/.env)",
      "Read(//**/.env.*)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(**/secrets/**)",
      "Bash(curl:*)",
      "Bash(wget:*)"
    ]
  },
  "disableAutoMode": "disable",
  "allowManagedPermissionRulesOnly": true,
  "allowManagedHooksOnly": true,
  "allowManagedMcpServersOnly": true,
  "allowedMcpServers": [{ "serverUrl": "https://mcp.internal.example.com/*" }],
  "strictKnownMarketplaces": [],
  "disableSkillShellExecution": true,
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "excludedCommands": [],
    "filesystem": {
      "denyRead": ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube"],
      "allowManagedReadPathsOnly": true
    },
    "credentials": {
      "files": [
        { "path": "~/.ssh", "mode": "deny" },
        { "path": "~/.aws/credentials", "mode": "deny" }
      ],
      "envVars": [
        { "name": "GITHUB_TOKEN", "mode": "deny" },
        { "name": "AWS_SECRET_ACCESS_KEY", "mode": "deny" }
      ]
    },
    "network": {
      "allowedDomains": ["registry.npmjs.org", "github.com"],
      "allowManagedDomainsOnly": true,
      "allowAllUnixSockets": false
    },
    "enableWeakerNestedSandbox": false
  },
  "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1"
  },
  "cleanupPeriodDays": 7,
  "requiredMinimumVersion": "2.1.251"
}
```

Warning: `allowManagedPermissionRulesOnly: true` discards user and project **deny** rules as well as allow rules: the managed list becomes the whole policy, `--allowedTools` is ignored, "always allow" choices disappear, and no new rules are saved. Make the managed list complete before enabling it. The same completeness requirement applies to `allowManagedHooksOnly` and `sandbox.filesystem.allowManagedReadPathsOnly`. `sandbox.excludedCommands` has no managed lock at all; keep the managed list narrow and expect developers to append to it. `github.com` in `allowedDomains` is itself an exfiltration channel (gists, PR bodies, issue comments).

### Hook scripts

`deny-secrets.sh`, **official-derived**: the docs' "Block edits to protected files" example, verbatim. As published it covers Edit/Write only.

```bash
#!/bin/bash
# protect-files.sh

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

# Normalize Windows backslash separators so the patterns below match
FILE_PATH="${FILE_PATH//\\//}"

PROTECTED_PATTERNS=(".env" "package-lock.json" ".git/")

for pattern in "${PROTECTED_PATTERNS[@]}"; do
  if [[ "$FILE_PATH" == *"$pattern"* ]]; then
    echo "Blocked: $FILE_PATH matches protected pattern '$pattern'" >&2
    exit 2
  fi
done

exit 0
```

To cover reads with the baseline's `Read|Grep|Glob|Edit|Write|NotebookEdit` matcher, read the right input field per tool: `file_path` for Read/Edit/Write, `path` + `pattern` for Grep/Glob, `notebook_path` for NotebookEdit. `[UNVERIFIED: the docs publish no read-blocking hook example; the field names come from the permissions page's parameter-matching section.]`

`block-egress.sh`, **composed, `[UNVERIFIED]`**: the hook contract is documented, this script is not.

```bash
#!/bin/bash
# block-egress.sh  -- PreToolUse, matcher "Bash|PowerShell"
INPUT=$(cat)
CMD=$(jq -r '.tool_input.command // empty' <<<"$INPUT")

# Any tool that can open a socket, plus common exfil idioms.
if printf '%s' "$CMD" | grep -Eqi '(^|[^[:alnum:]_])(curl|wget|nc|ncat|netcat|telnet|scp|sftp|rsync|ssh|ftp)([^[:alnum:]_]|$)|/dev/(tcp|udp)/|python[0-9.]*[[:space:]]+-c.*(socket|urllib|requests)|node[[:space:]]+-e.*(http|fetch)'; then
  echo "Blocked: outbound network commands are not permitted in this repo." >&2
  exit 2
fi
exit 0
```

It is a string matcher on a shell command and is defeatable by base64, variable indirection, or a script file. Treat it as a speed bump; `sandbox.network` is the real control. The docs make the same point about hook `if` filters: use the permission system, not a hook, to enforce a hard allow or deny.

## Verify at runtime

- `/status`: the `Setting sources` line names every settings file actually loaded and which managed source applies. Use it to confirm a file you edited is being read at all.
- `/permissions`: every effective rule and the file it came from; the Auto mode tab shows the classifier's rules.
- `/sandbox`: Mode, Overrides, Config (the "Denied within allowed" list resolves protected paths for this machine), Dependencies (confirms bubblewrap/socat/seccomp are present, i.e. that the sandbox will not fail open).
- `claude doctor`: lists rejected settings entries, skipped `mcp__(...)` rules, `injectHosts` that can never match, and unreliable IPv6 domain spellings. Run it after every settings edit; this is how inert rules surface.
- `claude auto-mode defaults`: prints the classifier's full built-in rule lists as JSON.
- `claude --version`: compare against `2.1.251`; below that, the symlink-swap and Grep/Glob-through-symlink deny bypasses are unfixed, and a managed `requiredMinimumVersion` should pin at or above it.
- `/context`: shows which memory files loaded.

## Sources

All under `https://code.claude.com/docs/en/` (the former `docs.anthropic.com/en/docs/claude-code/*` URLs 301 here):

- <https://code.claude.com/docs/en/settings>: hierarchy, precedence, cloud sessions, managed exceptions
- <https://code.claude.com/docs/en/settings-reference>: every key with scope, type, default
- <https://code.claude.com/docs/en/permissions>: rule syntax, path anchoring, Bash internals, WebFetch, MCP, Cd, workspace trust
- <https://code.claude.com/docs/en/permission-modes>: modes, auto-mode classifier, protected paths, critical paths
- <https://code.claude.com/docs/en/sandboxing>: OS support, filesystem/network layers, credentials, limitations
- <https://code.claude.com/docs/en/sandbox-environments>: containers, VMs, sandbox-runtime
- <https://code.claude.com/docs/en/hooks>: events, exit codes, decision control
- <https://code.claude.com/docs/en/hooks-guide>: worked examples, limitations, hooks vs permission modes
- <https://code.claude.com/docs/en/security>: safeguards, prompt injection, MCP security
- <https://code.claude.com/docs/en/data-usage>: retention, telemetry services, WebFetch preflight
- <https://code.claude.com/docs/en/env-vars>: environment variables
- <https://code.claude.com/docs/en/memory>: CLAUDE.md locations, `@` imports, external-import approval
- <https://code.claude.com/docs/en/claude-directory>: `.claude/` and `~/.claude/` contents, plaintext storage
- <https://code.claude.com/docs/en/context-window>: what loads at startup, environment-info block
- <https://code.claude.com/docs/en/mcp>: MCP configuration
- <https://code.claude.com/docs/en/managed-mcp>: org MCP controls
- <https://code.claude.com/docs/en/managed-settings>: policy delivery paths
- <https://code.claude.com/docs/en/cli-reference>: `--restricted`, `--bare`, `--safe-mode`, `--setting-sources`
- <https://code.claude.com/docs/en/auto-mode-config>: classifier rules and `permissions.ask` recipes
- <https://code.claude.com/docs/en/changelog>: version-gated fixes; mirrors the GitHub CHANGELOG
- <https://github.com/anthropics/claude-code/tree/main/examples/settings>: `settings-lax.json`, `settings-strict.json`, `settings-bash-sandbox.json` (community-maintained, may be incorrect)
- <https://json.schemastore.org/claude-code-settings.json>: editor validation schema (lags the newest releases)
