# Controls, gates, and deny lists

Shared vocabulary for every harness reference. A finding is *protected* only when an **enforced** tier (T1–T5) covers it; T6–T7 are **advisory** and never close a finding on their own.

## Control tiers

Ranked strongest → weakest. Controls low on this list are routinely mistaken for controls high on it.

| Tier | Control | Stops | Does NOT stop |
|---|---|---|---|
| **T1** | OS sandbox (Seatbelt, bubblewrap/Landlock, container, VM) | Subprocesses and agent-written scripts reading denied paths; writes outside the boundary; with network isolation, unapproved egress | Disclosure of anything it *allows* to be read (the sandbox "does not change what is sent to the model"); DNS if the resolver is allowed; domain fronting past a non-TLS-terminating proxy; Unix-socket escapes (`docker.sock`); escalation via writable `$PATH` or shell rc files |
| **T2** | Egress allowlist (default-deny firewall, proxy, no route) | `curl` to attacker hosts; most naive exfil | DNS exfil; smuggling to an *allowed* domain (gist, PR, public repo); MCP servers and setup steps that run outside the enforcement point |
| **T3** | Credential scrub (env unset/mask, launch shell without secrets, short-lived tokens) | `env`/`printenv` dumping tokens into the transcript; tokens leaving with an escaped request (mask) | Secrets in files the agent may read; ambient auth stored in files (`~/.aws/credentials`, `gh` hosts) unless also denied |
| **T4** | Harness deny/ask rule on paths, tools, commands | The harness's own Read/Edit/Bash/WebFetch calls that match; removing a tool from the model's context entirely | Arbitrary subprocesses (`python -c "open('.env')"`); argument injection and interpreter/wrapper evasion (`npx`, `docker exec`, `devbox run`); encoding (`base64 -d \| sh`); MCP tools |
| **T5** | Hook / pre-tool gate (deterministic program inspecting each call) | Whatever it can express in code on its trigger surface, including content-based egress DLP | Anything outside its trigger surface; a session that rewrites hook config; the hook's own bugs; fail-open on error/timeout |
| **T6** | Ignore file (`.gitignore`, `.cursorignore`, `.geminiignore`, `.aiderignore`, `.clineignore`, `.rooignore`, `.kiroignore`) | Accidental indexing, @-mention inclusion, search noise | `cat`, any subprocess, any MCP server; vendors say so verbatim (Cursor: terminal and MCP "cannot block access"; Cline: "not a security or access-control boundary") |
| **T7** | Instruction file (`AGENTS.md`, `CLAUDE.md`, rules, "block instructions" for a classifier) | Well-intentioned model error, somewhat | Anything adversarial; competes with injected instructions; dropped under context pressure. Never the answer to "what stops this?" for a Critical finding |

Two harms need separate controls:

- **Disclosure**: private data enters the transcript and reaches the provider. Governed by *read scope* (T3, T4 path rules, T1 `denyRead`). A sandbox alone does nothing here.
- **Exfiltration**: data reaches a third party the agent contacted, usually via prompt injection. Governed by T1 network isolation, T2, and ask-gates.

An agent with read access to private files, exposure to untrusted content (repo files, issues, web pages, dependency READMEs, MCP tool descriptions), and any outbound channel holds the full *lethal trifecta*. Read-only access is not a safe posture while the shell is an exit.

## Harness capability matrix

Which tiers each harness can reach at all, and whether a repo file can carry the policy. ✅ documented and enforceable · ⚠️ partial or weak · ❌ absent. Details and gotchas live in the per-harness reference.

| Capability | Claude Code | Codex CLI | OpenCode | Gemini CLI | Cursor | Copilot CLI | Aider | Cline | Roo | Amp | Kiro |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Repo-committable policy | ✅ `.claude/settings.json` (some keys user/managed-only) | ⚠️ user config; profiles not repo-scoped | ✅ `opencode.json` | ❌ workspace policies inert; `.gemini/settings.json` partial | ✅ `.cursor/cli.json`, `permissions.json`, `sandbox.json` | ✅ `.github/copilot/settings.json` | ⚠️ `.aider.conf.yml` (no perms) | ❌ | ❌ | ❌ | ❌ |
| Deny reads of secret paths (T4) | ✅ `Read(...)` | ✅ permission profile only; `sandbox_mode` grants all reads | ✅ `permission.read` (read tool only) | ✅ policy `deny` (user/admin tier) | ✅ `Read(...)` in `cli.json` | ⚠️ `--deny-tool` / saved approvals | ❌ | ❌ | ⚠️ `.rooignore` | ✅ `reject` | ✅ `fs_read` deny |
| Deny precedence | ✅ deny first | ✅ | ❌ **last match wins** | ✅ priority | ✅ (CLI) | ✅ | n/a | n/a | n/a | ✅ | ✅ |
| OS sandbox (T1) | ✅ macOS/Linux/WSL2, **not native Windows** | ✅ Seatbelt/bwrap; Windows Sandbox | ❌ | ✅ seatbelt/docker | ✅ but `~/.ssh` readable | ✅ MXC | ❌ | ❌ | ❌ | ✅ e2b | ⚠️ |
| Egress allowlist (T2) | ✅ `sandbox.network` | ✅ `network_proxy` | ⚠️ `webfetch` perm only | ✅ `sandboxNetworkAccess` | ✅ `networkPolicy` + SSRF blocks | ✅ `allowedUrls`/`deniedUrls` | ❌ | ❌ | ❌ | ❓ | ⚠️ |
| Credential scrub (T3) | ✅ `sandbox.credentials`, env scrub | ✅ `shell_environment_policy` (off by default) | ❌ | ✅ redaction (off by default) | ⚠️ cloud only | ❓ | ❌ | ❌ | ❌ | ✅ redaction | ❌ |
| Hooks (T5) | ✅ | ✅ | ⚠️ plugins | ✅ | ❌ | ✅ reads `.claude` hooks | ❌ | ❌ | ❌ | ⚠️ delegate | ✅ |
| Kill switch for yolo | ✅ `disableBypassPermissionsMode` | ✅ `requirements.toml` | ❌ | ✅ `disableYoloMode` + admin | ❌ | ✅ `disableBypassPermissionsMode` | ❌ | ❌ | ❌ | ❓ | ⚠️ |

## What an ask-gate must cover

`ask` beats `deny` for anything with legitimate uses: capability stays, a human stays in the loop. Gate at minimum:

| Gate | Why |
|---|---|
| Outbound network not on the allowlist: `curl wget nc ncat socat telnet ssh scp sftp rsync`, `Invoke-WebRequest`/`iwr`, `Invoke-RestMethod`, `certutil -urlcache`, `bitsadmin`, WebFetch, browser tools | Primary exfil channel |
| DNS tools: `ping dig nslookup host` | DNS exfil (CVE-2025-55284 used auto-approved `ping`/`nslookup` to leak `.env` as subdomains); HTTP allowlists do not cover it |
| `git push`, `git remote add/set-url`, `git config` touching remotes/hooks/`insteadOf`/`core.fsmonitor` | Exfil by push; persistence; arbitrary execution |
| Public-artifact creation: `gh repo create`, `gh gist create`, `gh pr create`, `gh issue create`, `gh api` | The s1ngularity and GitHub-MCP exfil route |
| Package publish: `npm/yarn/pnpm publish`, `twine upload`, `cargo publish`, `gem push`, `docker push`, `nuget push`, `helm push` | Exfil + downstream poisoning |
| Credential reads: `~/.ssh ~/.aws ~/.config/gcloud ~/.azure ~/.kube ~/.docker ~/.gnupg ~/.netrc ~/.git-credentials`, browser profiles, `**/.env*` | Disclosure: usually deny; ask only if genuinely needed |
| Env/identity enumeration: `env printenv set export -p declare -x`, `Get-ChildItem Env:`, `whoami hostname id groups`, `ifconfig ipconfig ip addr getmac netstat lsof -i`, `uname -a systeminfo`, `aws sts get-caller-identity`, `gcloud config list`, `az account show`, `gh auth status` | Disclosure + machine fingerprinting |
| Privilege: `sudo doas su runas`, `Start-Process -Verb RunAs`, `--privileged` | Escapes the boundary |
| Destructive: `rm -rf`, `git reset --hard`, `git clean -fdx`, `git push --force`, `Remove-Item -Recurse -Force`, `DROP/TRUNCATE`, `terraform apply/destroy`, `kubectl delete`, `aws s3 rm` | Blast radius |
| Ambient-auth infrastructure CLIs: `aws gcloud az kubectl helm terraform pulumi docker podman doctl flyctl vercel heroku stripe psql mysql mongo redis-cli` | Live authenticated channel into production |
| Interpreters that defeat command patterns: `python -c`, `node -e`, `ruby -e`, `perl -e`, `php -r`, `bash -c`, `sh -c`, `eval`, `base64 -d`, `xxd -r` | Trivial bypass of every T4 command rule |
| Installing/enabling an MCP server, plugin, skill, extension; editing the harness's own config (`.claude/settings.json`, `.mcp.json`, hooks, `AGENTS.md`); writing `.git/hooks`, shell rc files, anything on `$PATH` | New trifecta leg; self-escalation; persistence |

Approval fatigue is a failure mode: a gate that fires fifty times a session gets click-through-approved. Let T1/T2 absorb the routine and reserve `ask` for the consequential. Approval prompts can also lie: argument injection into an already-approved command bypasses the human (Trail of Bits, 2025-10), and MCP approval dialogs truncate tool descriptions.

## Universal deny list: path globs

Translate into the harness's syntax (see the per-harness reference for anchoring rules; on Windows the Claude Code form is `//c/Users/*/...`, and a POSIX-only list is a silent no-op).

```
# Repo-local secrets
**/.env  **/.env.*  **/*.env  **/.envrc
**/*.pem  **/*.key  **/*.p12  **/*.pfx  **/*.jks  **/*.keystore  **/*.asc  **/*.gpg  **/*.ppk
**/id_rsa*  **/id_dsa*  **/id_ecdsa*  **/id_ed25519*
**/.netrc  **/_netrc  **/.pgpass  **/.my.cnf  **/.npmrc  **/.pypirc  **/.yarnrc.yml
**/kubeconfig  **/*.kubeconfig  **/terraform.tfstate*  **/*.tfvars  **/.terraform/**
**/secrets/**  **/*secret*.json  **/*credential*.json  **/serviceAccount*.json  **/firebase-adminsdk-*.json
**/*.har  **/.git/config  **/.git/credentials  **/.mcp.json
# Optional re-allow only after verifying it holds no real values:  **/.env.example

# Home credential stores
~/.ssh/**  ~/.aws/**  ~/.azure/**  ~/.config/gcloud/**  ~/.kube/**  ~/.docker/**  ~/.gnupg/**
~/.netrc  ~/.authinfo*  ~/.git-credentials  ~/.config/git/credentials  ~/.config/gh/**
~/.npmrc  ~/.pypirc  ~/.cargo/credentials*  ~/.gem/credentials  ~/.m2/settings.xml
~/.gradle/gradle.properties  ~/.nuget/NuGet.Config  ~/.composer/auth.json  ~/.terraform.d/**
~/.password-store/**  ~/.config/1Password/**  ~/.local/share/keyrings/**  ~/Library/Keychains/**
~/.bash_history  ~/.zsh_history  ~/.*_history  ~/.local/share/fish/fish_history

# Other agents' credentials and transcripts
~/.claude/.credentials.json  ~/.claude.json  ~/.claude/history.jsonl  ~/.claude/projects/**
~/.codex/auth.json  ~/.codex/sessions/**  ~/.gemini/oauth_creds.json  ~/.cursor/**
~/.config/opencode/**  ~/.aider*

# Browser profiles
~/.config/google-chrome/**  ~/.config/chromium/**  ~/.mozilla/**
~/Library/Application Support/Google/Chrome/**  ~/Library/Application Support/Firefox/**

# Windows equivalents (Claude Code normalises C:\Users\x → /c/Users/x)
//c/Users/*/.ssh/**  //c/Users/*/.aws/**  //c/Users/*/.kube/**  //c/Users/*/.azure/**
//c/Users/*/AppData/Roaming/gh/**  //c/Users/*/AppData/Roaming/npm/etc/npmrc
//c/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
//c/Users/*/AppData/Local/Google/Chrome/User Data/**  //c/Users/*/AppData/Local/Microsoft/Edge/User Data/**
```

## Universal deny list: commands

**Deny outright** (no legitimate use in a coding session): `sudo *`, `doas *`, `su *`, `runas *`, `chmod 777 *`, `chown -R *`, `mkfs*`, `dd if=* of=/dev/*`, `diskutil *`, `format *`, `curl * | sh`, `curl * | bash`, `wget * | sh`, `iwr * | iex`, `history`, `cat ~/.bash_history`, `cat ~/.ssh/*`, `cat ~/.aws/*`, `cat ~/.netrc`, `cat ~/.git-credentials`, `gpg --export-secret-keys *`, `security dump-keychain *`.

**Gate with ask**: every row of the ask-gate table above.

Denylists lose to obfuscation; prefer allowlists where the harness offers them, and pair every command rule with a T1 sandbox.

## Env-var patterns to scrub

Use as both a scrub list and a scanner signature (report names, never values). Prefer **mask** where a tool genuinely needs the credential, **deny** for anything the session should not use.

```
*_KEY *_KEYS *_SECRET *_SECRETS *_TOKEN *_PASSWORD *_PASSWD *_PWD *_CREDENTIAL*
*_API_KEY *_ACCESS_KEY *_PRIVATE_KEY *_CLIENT_SECRET *_AUTH *_SESSION *_COOKIE
*_DSN *_URI *_URL                      # DATABASE_URL, REDIS_URL — creds in userinfo
AWS_* GOOGLE_APPLICATION_CREDENTIALS GCP_* GCLOUD_* AZURE_* ARM_*
GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN BITBUCKET_* CI_JOB_TOKEN
NPM_TOKEN PYPI_TOKEN TWINE_PASSWORD CARGO_REGISTRY_TOKEN NUGET_API_KEY DOCKER_PASSWORD
ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY GOOGLE_API_KEY HF_TOKEN REPLICATE_API_TOKEN
STRIPE_* TWILIO_* SENDGRID_* SLACK_* DATADOG_* NEW_RELIC_* SENTRY_AUTH_TOKEN
VAULT_TOKEN CONSUL_HTTP_TOKEN NOMAD_TOKEN TF_VAR_* KUBECONFIG
SSH_AUTH_SOCK                          # a handle to live keys, not a secret itself
```

Reachable via `env`, `printenv`, `set`, `/proc/self/environ`, `/proc/<pid>/environ`, `ps auxwwe`, `docker inspect`, PowerShell `Get-ChildItem Env:`, and any script the agent writes. Most read-only command allowlists include `cat`, so `cat /proc/self/environ` is auto-approved on many setups.

## False-positive trade-offs (state these in the report)

| Rule | Breaks | Mitigation |
|---|---|---|
| Deny `**/.env*` | Editing `.env.example`; scaffolding a new `.env` | Re-allow the example file after verifying it is placeholder-only; or `ask` |
| Deny `~/.aws/**`, `~/.config/gh/**` | `aws`, `gh`, `terraform` stop authenticating | Mask with host injection where supported; or run those commands outside the sandbox with explicit approval |
| Deny/gate `curl`, `wget` | `curl localhost:3000`, install scripts | Allowlist `localhost`/`127.0.0.1` and known hosts; use the harness's fetch tool with a domain allowlist |
| Gate `ping`/`dig`/`nslookup` | Network debugging | Accept the friction: this is the DNS channel |
| Gate `docker *` | Containerised workflows | Allow `docker ps`/`logs`; gate `run`/`exec`/`push`; never mount `docker.sock` into the sandbox |
| Gate `git push *` | High prompt frequency | Restrict to the current branch rather than gating every push; keep force-push gated |
| Deny `env`/`printenv` | Env debugging; build tools that shell out to `env` | Scrub the environment so `env` is harmless, rather than blocking `env` |
| Broad `git *` allow | Silently permits `git push` and `git -c core.fsmonitor=<script>` | Never wildcard before the subcommand |
| Path rules only | Any agent-written script bypasses them | Pair with T1 `denyRead` |
