# Cursor — hardening reference
Verified against: cursor.com docs as of 2026-08-30; changelog latest entry 2026-08-27. Docs reference behaviour "starting in Cursor 3.11".

## Config surfaces

Two separate permission systems — the IDE agent (`permissions.json`) and the Cursor CLI (`cli.json`). Do not conflate them.

| File | Scope | Committed to repo? | Precedence / trust notes |
|---|---|---|---|
| `.cursorignore` | repo | **yes** | Blocks the read/edit tools and `@`-mentions. **Not** the terminal or MCP. Write-protected by the sandbox — the agent cannot edit it. Gitignore negation semantics: a file under an excluded parent directory cannot be re-included. |
| `.cursorindexingignore` | repo | yes | Indexing-only — excluded from the codebase index but still agent-accessible. Strictly weaker than `.cursorignore`. |
| `~/.cursor/permissions.json` | user | no | IDE agent. Concatenated with the repo file. |
| `<workspace>/.cursor/permissions.json` | repo | **yes** | IDE agent. Precedence: team admin dashboard > `permissions.json` (per-user + per-repo **concatenated**) > IDE settings UI. When a field is defined here it "fully replaces" the IDE allowlist for that type and the IDE UI becomes read-only; an empty array after concatenation = empty allowlist with no IDE fallback. Only active when a Run Mode is enabled. |
| `~/.cursor/cli-config.json` | user | no | Cursor CLI, global. Also holds the approval mode. |
| `<project>/.cursor/cli.json` | repo | **yes** | Cursor CLI, **permissions only**. The only Cursor mechanism with true deny-precedence. |
| `~/.cursor/sandbox.json` | user | no | Lower priority than the repo file. |
| `<workspace>/.cursor/sandbox.json` | repo | **yes** | Merge order: per-user < per-repo < team-admin < hardcoded security rules. Paths union; network allow lists union unless a team-admin policy replaces them; deny lists always union; restrictive settings win. |
| Team admin dashboard | org | no | Above all local files for `permissions.json`; can replace network allow lists. |
| Cursor Settings UI (Run Modes, Indexing → Ignore Files, Privacy Mode) | user/org | no | Hierarchical ignore moved to `Cursor Settings > Indexing > Ignore Files` in Cursor 3.11. |
| Cloud agent secrets & network modes | org | no | Env Variables / Runtime Secrets / Build Secrets; network mode set at user, environment, and team level. |

Cursor ships a **default** ignore list including `**/.env*`, lock files, binaries, `node_modules/`, `.git/`.

Always write-protected regardless of config: `.cursor/*.json`, `.cursor/**/*.json`, `.cursor/.workspace-trusted`, `.claude/*.json`, `.claude/**/*.json`, `.vscode/**`, `.code-workspace`, `.git/hooks/**`, `.git/config`, `.git/info/attributes`, `.cursorignore`. Writable `.cursor` subdirs: `rules/`, `commands/`, `worktrees/`, `skills/`, `agents/`. "Users cannot weaken these hardcoded protections locally."

## What each control actually stops

| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `.cursorignore` | T6 ignore file | "Code accessible by Agent, Tab, and Inline Edit" and "Code accessible via @ mention references" | Verbatim: "The terminal and MCP server tools used by Agent cannot block access to code governed by `.cursorignore`." Also: "While Cursor blocks ignored files, complete protection isn't guaranteed due to LLM unpredictability." |
| `.cursorindexingignore` | T6 ignore file | Inclusion in the codebase index | All agent tool access |
| `cli.json` `permissions.deny` → `Read(...)` | T4 harness deny rule | The CLI agent reading matched paths, including absolute paths outside the workspace | The IDE agent (different system); an MCP server reading the file |
| `cli.json` `permissions.deny` → `Shell(...)` | T4 harness deny rule | Matched command bases | Equivalent commands under another name or interpreter |
| `cli.json` `permissions.deny` → `WebFetch(*)` | T2 egress allowlist | The CLI's fetch tool | `curl`/`wget` if `Shell` allows them; MCP egress |
| `permissions.json` `terminalAllowlist` | — (allowlist only) | Nothing — it *permits*. **Prefix-based and case-sensitive**: `git` matches anything starting with `git` | It is not a denylist; there is no deny field |
| `permissions.json` `mcpAllowlist` | — (allowlist only) | Nothing — it permits `server:tool` pairs. Case-insensitive; globs within names | Servers reached outside a Run Mode |
| `permissions.json` `autoRun.block_instructions` | T7 instruction file | Whatever a natural-language classifier decides to block | Anything the classifier misreads. This is a prompt, not a rule |
| Run Mode **Auto-review** | T1 OS sandbox (partial) | "Allowlisted calls run immediately. Other shell commands run in the sandbox when possible" | Anything when the sandbox is not possible |
| Run Mode **Run Everything** | — | Nothing. "Every tool call runs automatically" — no sandboxing, no classifier | This is Cursor's YOLO equivalent |
| `sandbox.json` `type` | T1 OS sandbox | `workspace_readwrite` (default) / `workspace_readonly` constrain writes | Reads — see the `~/.ssh` gap below. `insecure_none` disables it |
| `sandbox.json` `networkPolicy` | T2 egress allowlist | `default: "deny"` blocks egress; `deny` list always overrides `allow`. RFC 1918 ranges (`10.x`, `172.16.x`, `192.168.x`, `127.x`), IPv6 private ranges, and the metadata endpoint `169.254.169.254` are **blocked by default to prevent SSRF** — this kills the classic IMDS credential grab | Egress from outside the sandbox (Run Everything mode) |
| Cloud **Runtime Secrets** | T3 credential scrub | "their contents are redacted from the agent's tool call results, chat transcript, commits, and commit messages" | Verbatim: "users accessing the terminal environment can still view them" |
| Cloud **Build Secrets** | T3 credential scrub | Available at Docker build only, never to the running agent | — |
| Cloud **Environment Variables** | — | Nothing; visible to the agent, intended for non-sensitive config | — |
| Privacy Mode | — (data routing) | Customer data used for training by Cursor; Cursor states ZDR agreements with providers; cached file contents temporary and never training data | Providers "may run risk classifiers"; data triggering abuse detectors may be stored for investigation |

## Rule semantics you must get right

1. **`.cursorignore` does not cover the agent terminal or MCP tools.** Documented verbatim. `cat .env` in the agent terminal is unaffected.
2. **The sandbox leaves `~/.ssh` readable.** Verbatim from the sandbox reference: "SSL certificates and `~/.ssh` remain readable." Combined with (1), **`cat ~/.ssh/id_rsa` is blocked by neither of Cursor's two headline controls.** The only stops are a `Read(~/.ssh/**)` deny in `.cursor/cli.json`, an `autoRun.block_instructions` hint (classifier, best-effort), or a human approval. State this explicitly in any Cursor hardening report.
3. **`permissions.json` has allowlists only — no denylist.** Blocking is expressed as natural-language `autoRun.block_instructions` handed to a classifier, e.g. `"Every AWS CLI command should go through approval first."` Score that as fundamentally weaker than a glob/regex deny rule.
4. **`cli.json` is the opposite: deny rules take precedence over allow rules.** This is the only Cursor surface with real deny precedence, and it is repo-committable. Its absence is the headline finding for a Cursor repo.
5. **`terminalAllowlist` is prefix matching, case-sensitive.** A bare `git` entry allows `git config --global core.pager 'sh -c ...'`. Treat bare `git`, `bash`, `sh`, `python`, `node`, `npm`, `docker` as escape hatches. `npm:install*` is the form that separates base command from arg globs.
6. **`permissions.json` "fully replaces" the IDE allowlist for any field it defines**, and the IDE UI goes read-only. Per-user and per-repo files concatenate, so a repo can only *add* — but adding is enough to widen.
7. `permissions.json` allowlists are **only active when a Run Mode is enabled**.
8. CLI permission tokens: `Shell(commandBase)`, `Read(pathOrGlob)`, `Write(pathOrGlob)`, `WebFetch(domainOrPattern)`, `Mcp(server:tool)`. Globs use `**`, `*`, `?`. Relative paths are workspace-scoped; absolute paths target external files. WebFetch: `*` = all, `*.example.com` = subdomains, `example.com` = exact only.
9. CLI approval modes: `allowlist`, `auto-review`, `unrestricted`. IDE Run Modes: Auto-review (recommended), Allowlist, Run Everything.
10. `sandbox.json` merges rather than replaces, and **restrictive settings win** — so a repo file can tighten but a repo file with `type: "insecure_none"` cannot loosen below hardcoded rules; check the merged result, not one file.
11. **The vendor disclaims all of it as a boundary.** "Allowlists and autoRun instructions are best-effort convenience"; Run Modes are "best-effort guardrails rather than a hard security boundary". Terminal commands require approval by default and "Agents cannot make arbitrary network requests with default settings" (restricted to GitHub, direct link retrieval, web search providers).
12. Cloud agents: do not wildcard artifact-upload allowlists — the docs warn that "creates an exfiltration path for a prompt-injected agent." Egress IPs are published at `cursor.com/docs/ips.json`.

## Detection checklist

**Repo-visible:**

| Check | Severity | Where to look |
|---|---|---|
| Repo docs, README, or scripts instructing users to enable **Run Everything** mode or CLI `unrestricted` | Critical | `README*`, `CONTRIBUTING*`, `.cursor/rules/**`, `Makefile`, CI |
| `.cursor/sandbox.json` with `"type": "insecure_none"` or `networkPolicy.default: "allow"` | Critical | `<repo>/.cursor/sandbox.json` |
| `.cursor/sandbox.json` `additionalReadwritePaths` / `additionalReadonlyPaths` including `~`, `/`, `~/.ssh`, `~/.aws` | Critical | same file |
| **`<repo>/.cursor/cli.json` absent** — no deny-precedence mechanism in play at all | High | `<repo>/.cursor/` |
| `cli.json` present but missing `Read(.env*)`, `Read(~/.ssh/**)`, `Read(~/.aws/**)`, `Shell(env)`, `Shell(printenv)`, `Shell(curl)`, `Shell(wget)`, or a restrictive `WebFetch(...)` | High | `<repo>/.cursor/cli.json` → `permissions.deny` |
| No `Read(~/.ssh/**)` deny specifically — the sandbox leaves it readable | High | same |
| `.cursorignore` is the only protection present (ignore-file-only posture) | High | repo root |
| `.cursor/permissions.json` `terminalAllowlist` containing bare `git`, `bash`, `sh`, `python`, `node`, `npm`, `docker` | High | `<repo>/.cursor/permissions.json` |
| `.cursor/permissions.json` `mcpAllowlist` containing `*:*` | High | same |
| `.cursorignore` absent or not covering `.env*`, `*.pem`, `*.key`, `id_rsa*`, `.netrc`, `.npmrc`, `secrets/`, `credentials*`, `*.tfstate`, `*.kdbx` | Medium — annotate that it does not cover the terminal or MCP | repo root |
| `.cursorindexingignore` used where `.cursorignore` was intended (indexing-only, weaker) | Medium | repo root |
| `.cursor/sandbox.json` absent, so no network policy is asserted | Medium | `<repo>/.cursor/` |
| `disableTmpWrite` / `enableSharedBuildCache` left at defaults where the repo handles secrets | Low | `<repo>/.cursor/sandbox.json` |
| `autoRun.block_instructions` does not mention credentials/env/network | Low — weak but shows intent | `<repo>/.cursor/permissions.json` |

**Must verify out-of-band** (user config / Cursor settings UI / team dashboard):

| Check | Severity | Where to look |
|---|---|---|
| Run Mode is **Run Everything**, or CLI approval mode is `unrestricted`, with no container | Critical | Cursor Settings → Run Modes; `~/.cursor/cli-config.json` |
| Cloud agent network mode is "allow all" | Critical | Cursor cloud agent settings; team dashboard |
| Secrets stored as plain **Environment Variables** rather than **Runtime Secrets** or **Build Secrets** | High | cloud agent secret configuration |
| `~/.cursor/permissions.json` adding broad allowlist entries that concatenate with the repo file | High | user config |
| `~/.cursor/sandbox.json` weaker than the repo file (merge is union; still confirm) | Medium | user config |
| **Privacy Mode** off — not detectable from the repo; on by default for Enterprise and enforceable team-wide | Medium | Cursor Settings → Privacy; team dashboard |
| Hierarchical ignore disabled (Cursor 3.11: `Cursor Settings > Indexing > Ignore Files`) | Low | Cursor Settings |
| Team admin dashboard policies replacing local network allow lists | Info | team dashboard |

## Hardened baseline

### `<project>/.cursor/cli.json` — repo-committable, deny-precedence, the load-bearing file

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

### `<workspace>/.cursor/sandbox.json` — repo-committable, higher priority than the user file

```json
{
  "type": "workspace_readwrite",
  "additionalReadwritePaths": [],
  "additionalReadonlyPaths": [],
  "disableTmpWrite": true,
  "enableSharedBuildCache": false,
  "networkPolicy": {
    "default": "deny",
    "allow": ["registry.npmjs.org", "*.githubusercontent.com", "github.com"],
    "deny": ["169.254.169.254"]
  }
}
```

Field defaults for reference: `type` = `"workspace_readwrite"` (also `"workspace_readonly"`, `"insecure_none"`); `additionalReadwritePaths` = `[]`; `additionalReadonlyPaths` = `[]`; `disableTmpWrite` = `false`; `enableSharedBuildCache` = `false`; `networkPolicy.default` = `"deny"`; `networkPolicy.allow` accepts exact domain, `*.example.com`, or CIDR; `networkPolicy.deny` always blocks and overrides allow.

### `<workspace>/.cursor/permissions.json` — repo-committable, allowlist-only

```json
{
  "mcpAllowlist": [],
  "terminalAllowlist": ["git status", "git diff", "npm test", "npm:run test*"],
  "autoRun": {
    "allow_instructions": [
      "Read-only inspection of source files in the workspace may run without approval."
    ],
    "block_instructions": [
      "Every command that reads environment variables or credential files should go through approval first.",
      "Every AWS CLI command should go through approval first.",
      "Every outbound network request should go through approval first."
    ]
  }
}
```

An empty `mcpAllowlist` after concatenation means an empty allowlist with **no IDE fallback** — that is the intended lockdown, but confirm the per-user file is not adding entries.

### `.cursorignore` — repo root

```
.env
.env.*
*.pem
*.key
id_rsa*
id_ed25519*
.netrc
.npmrc
secrets/
credentials*
*.tfstate
*.kdbx
```

**Ignored / not settable from repo scope:** Privacy Mode, Run Mode selection, cloud agent network mode and secret classes, team admin policies, and the Cursor Settings indexing options. None of these can be asserted by a committed file — report them as user/admin actions. Note also that `.cursor/*.json` and `.cursorignore` are hardcoded write-protected, so the agent cannot tamper with the files above once committed.

## Verify at runtime

- IDE: `Cursor Settings` → Run Modes (confirm not "Run Everything"); → `Indexing` → `Ignore Files` (confirm hierarchical ignore); → Privacy (confirm Privacy Mode).
- CLI: `cat ~/.cursor/cli-config.json` for the approval mode; `cat <project>/.cursor/cli.json` for the deny list.
- Confirm concatenation, not replacement, by reading `~/.cursor/permissions.json` alongside `<workspace>/.cursor/permissions.json`.
- Confirm the merged sandbox posture by reading `~/.cursor/sandbox.json` and `<workspace>/.cursor/sandbox.json` together; restrictive settings win and deny lists union.
- Empirical checks in an agent terminal: `cat .env` (expect the `.cursorignore` gap — it will succeed unless `cli.json` denies it) and `cat ~/.ssh/id_rsa` (expect success under the sandbox alone; must be denied by `cli.json`).
- Network: with `networkPolicy.default: "deny"`, `curl https://169.254.169.254/` and an arbitrary external host should both fail from a sandboxed command.
- Cloud agents: compare outbound behaviour against the published egress IPs at `cursor.com/docs/ips.json`.

## Sources

- <https://cursor.com/docs/context/ignore-files>
- <https://cursor.com/docs/reference/permissions>
- <https://cursor.com/docs/agent/security>
- <https://cursor.com/docs/agent/security/run-modes>
- <https://cursor.com/docs/reference/sandbox>
- <https://cursor.com/docs/cli/reference/permissions>
- <https://cursor.com/docs/cli/reference/configuration>
- <https://cursor.com/docs/cloud-agent/security-network>
- <https://cursor.com/docs/enterprise/privacy-and-data-governance>
- <https://cursor.com/data-use>
