# Grading checklist

Harness-agnostic checks. Severity is the default; **escalate one level** when the provider retains or trains on transcripts, when the repo is employer- or client-owned, or when the machine holds production credentials. The per-harness reference adds harness-specific checks with the same severity scale.

Every finding records: check id · location · severity · the control (tier) protecting it now, or `unprotected` · the enforced control that would fix it.

## A. Secrets in reach

| # | Check | Severity |
|---|---|---|
| A1 | Secret-shaped files in the worktree (`.env*`, `*.pem`, `*.key`, `*.p12`, `id_rsa*`, `*.tfstate`, `.npmrc`, `serviceAccount*.json`, `*.har`), tracked, untracked, or ignored | Critical |
| A2 | `gitleaks dir` finds secrets in the worktree | Critical |
| A3 | `gitleaks git` / TruffleHog finds secrets in history only | Critical: `git log -p` is in reach |
| A4 | TruffleHog reports **verified** (live) credentials | Critical: rotate, deletion is not remediation |
| A5 | `.git/config` or `git remote -v` embeds a token | Critical |
| A6 | Notebook outputs, `*.har`, screenshots, `fixtures/` + `*.sql`/`*.csv` dumps present | High (Critical if real personal data) |
| A7 | Symlinks resolving outside the repo | High |
| A8 | `.gitignore` is the only thing "hiding" secrets that are on disk | High |
| A9 | MCP config (`.mcp.json`, `.cursor/mcp.json`, `opencode.json` `mcp.*`, `.gemini/settings.json` `mcpServers`) contains a literal token, or `{env:…}`/`{file:…}`/`$VAR` substitution feeding a remote URL | Critical |

## B. Machine and process state

| # | Check | Severity |
|---|---|---|
| B1 | Secret-looking env vars exported in the launching shell (name-pattern match; values never reported) | High |
| B2 | Credential dirs present and readable (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/.netrc`, `~/.git-credentials`, Windows `AppData` equivalents) | High (Critical if no T1/T4 deny covers them) |
| B3 | `SSH_AUTH_SOCK` set: agent forwarding reachable | High |
| B4 | Cloud instance / CI runner where `169.254.169.254` is reachable | Critical |
| B5 | `/var/run/docker.sock` reachable from the agent's boundary | Critical |
| B6 | `~/.kube/config` points at a non-local cluster | High |
| B7 | Sibling repos from other owners/clients under a parent of the working directory | High |
| B8 | Agent runs as root/Administrator or in an elevated shell | High |
| B9 | Shell history files readable and non-empty (`.bash_history`, `.zsh_history`, PSReadLine `ConsoleHost_history.txt`) | Medium |
| B10 | Corporate VPN / mesh (`tailscale`, `wg`) active during the session | Medium |

## C. Harness configuration

| # | Check | Severity |
|---|---|---|
| C1 | No harness config present at all, running on defaults | High (Critical for harnesses whose default is allow-all, e.g. OpenCode) |
| C2 | **Auto/YOLO mode** reachable outside a container/VM: `--dangerously-skip-permissions`, `--yolo`, `--full-auto`, `--dangerously-bypass-approvals-and-sandbox`, `--trust-all-tools`, `--allow-all`, `--yes-always`, `--auto`, `approval_policy = "never"`, `sandbox_mode = "danger-full-access"`, Cursor "Run Everything", `defaultMode: bypassPermissions` (in config, scripts, aliases, Makefiles, or CI) | Critical |
| C3 | No OS sandbox: not enabled, unsupported on this host (Claude Code on native Windows), fails open, or a permissive profile (Gemini `permissive-open`) | High |
| C4 | Sandbox enabled but filesystem layer disabled or `allowRead` re-opens `~` | High |
| C5 | Network unrestricted: no domain allowlist, no egress firewall, `*-open` profile, `networkPolicy.default: allow` | High |
| C6 | Egress allowlist present but admits `*`, `github.com` write paths, pastebins, or any user-writable host | Medium |
| C7 | Deny rules do not cover `.env` / `.env.*` | High |
| C8 | Deny rules do not cover home credential dirs | High |
| C9 | No env-var scrubbing/masking (empty `sandbox.credentials`, no subprocess scrub, Gemini redaction off, no `shell_environment_policy`) | High |
| C10 | Broad allow rules: `Bash(*)`, `Bash(git *)`, `Bash(python*)`, `Bash(npx *)`, `Bash(docker *)`, wildcard-before-subcommand, `WebFetch(domain:*)`, bare `git`/`npm`/`node` prefix allowlists, `tools.allowed: ["run_shell_command"]` | High |
| C11 | Denylist-style command rules where an allowlist is available | Medium |
| C12 | Unix sockets allowed through the sandbox (`docker.sock`) | Critical |
| C13 | Weakening flags: `enableWeakerNestedSandbox`, `allowAppleEvents`, `allowAllUnixSockets`, `enableWeakerNetworkIsolation`, `ignoreViolations`, `sandbox.excludedCommands` non-empty, `insecure_none` | High |
| C14 | Repo-scope config **widens** authority: allow rules, `additionalDirectories`, `trust: true` on MCP servers, repo-registered hooks, agent files with wider permissions, `enableAllProjectMcpServers: true` | High (Critical for repo-registered hooks: arbitrary code at session start) |
| C15 | No managed/org-level settings pinning the policy (team context only) | Medium |
| C16 | No hooks configured for pre-tool gating | Low: missed opportunity |
| C17 | An ignore file (T6) is the *only* protection for a sensitive path | High |
| C18 | An instruction file (T7) is the *only* protection for a sensitive path | High |
| C19 | Headless/non-interactive mode (`-p`, SDK, CI) on an unreviewed repo: trust dialogs never fire | Medium |
| C20 | **Inert** config. Known instances: rules honoured only from user/managed scope placed in a repo file; Gemini workspace-tier policies; a Codex permission profile alongside any `sandbox_mode` (the profile is silently overridden); Codex `sandbox_mode = "read-only"` relied on for read protection (it grants filesystem-wide read); `Write(...)`/`Glob(...)` path rules; mis-anchored `/path` in user settings; hooks with missing scripts or `exit 1`; POSIX-only paths on Windows | High: false sense of security |
| C21 | Personal override file tracked in git (`.claude/settings.local.json`, `.github/copilot/settings.local.json`) | High |

## D. Connected tools

| # | Check | Severity |
|---|---|---|
| D1 | MCP server with broad scope: filesystem rooted above the repo, DB server at prod, org-wide PAT | Critical |
| D2 | Third-party/unvetted MCP servers enabled; unpinned `npx -y` server commands | High |
| D3 | MCP servers run outside the sandbox/egress boundary (default for most harnesses) | High |
| D4 | Ambient-auth CLIs authenticated and ungated (`gh auth status`, `aws sts get-caller-identity`, `gcloud`, `az`, `kubectl` succeed; no `ask` rule) | High |
| D5 | Browser/computer-use tool enabled with a logged-in profile | Critical |
| D6 | One credential spans public and private scopes (the GitHub-MCP failure) | Critical |
| D7 | Plugins/skills/extensions from unvetted sources | High |

## E. Untrusted-content exposure

| # | Check | Severity |
|---|---|---|
| E1 | Session will read third-party content: issues, PRs, web pages, dependency source | High: trifecta leg |
| E2 | Repo carries agent-instruction files from untrusted contributors (`AGENTS.md`, `.cursor/rules`, `.github/copilot-instructions.md`, skills) | High |
| E3 | Hidden-instruction markers in repo content: invisible Unicode tags, zero-width characters, HTML comments with imperative text, base64 blobs in docs | High |
| E4 | Untrusted/forked/unreviewed repo without VM isolation | Critical |

## F. Provider and transcript

| # | Check | Severity |
|---|---|---|
| F1 | Provider tier retains or trains on transcripts, or terms unknown (assume yes): drives escalation of everything above | High |
| F2 | Prior session transcripts on disk readable by the current session (`~/.claude/projects/**`, `~/.codex/sessions/**` not denied) | High |
| F3 | Telemetry/OTel exporters shipping prompt or tool metadata off-box; session sharing enabled (`share: auto`) | Medium |
| F4 | Memory files writable by the session (injection persistence) | High |

## Verdict rule

First rule that matches:

1. Any **Critical** open → **DO NOT RUN** until remediated or an enforced boundary removes it from reach.
2. Three or more **High** open → **HARDEN FIRST**.
3. Any High, or only Medium/Low → **RUN WITH CARE**, residual risk listed.
4. Every check closed by an enforced (T1–T5) control → **HARDENED**.

Advisory (T6–T7) controls never close a check. Deletion of a secret never closes A2–A5; rotation does.
