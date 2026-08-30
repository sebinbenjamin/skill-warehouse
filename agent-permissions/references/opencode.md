# OpenCode: hardening reference
Verified against: docs + `main` source as of 2026-08-30. Latest release `v1.18.25` (2026-08-28). Canonical repo is `anomalyco/opencode`; `sst/opencode` redirects to it.

## Config surfaces

Layers **merge** (they do not replace), lowest → highest precedence.

| File | Scope | Committed to repo? | Precedence / trust notes |
|---|---|---|---|
| `.well-known/opencode` | remote | no | Layer 1, lowest. |
| `~/.config/opencode/opencode.json` | user | no | Layer 2. Only place to put machine-wide posture. |
| `$OPENCODE_CONFIG` (path to file) | env | no | Layer 3. |
| `opencode.json` / `opencode.jsonc` (project root) | repo | **yes** | Layer 4: **overrides the user layer**. A repo file can loosen a developer's personal hardening. JSON and JSONC both accepted; schema `https://opencode.ai/config.json`. |
| `.opencode/` (agents, plans, commands) | repo | yes | Layer 5. |
| `.opencode/agents/*.md` | repo | yes | Markdown + frontmatter; filename = agent id; frontmatter carries `mode` (`primary`/`subagent`/`all`), `permission`, `model`, `tools`. **Agent rules take precedence over the global `permission` block**; these files can widen. |
| `$OPENCODE_CONFIG_CONTENT` (inline JSON) | env | no | Layer 6. |
| Managed config files (system dirs) | machine | no | Layer 7. |
| macOS managed preferences (MDM) | machine | no | Layer 8, highest. |
| `AGENTS.md` | repo | yes | Instruction text only, no enforcement. |
| `~/.config/opencode/AGENTS.md` | user | no | Instruction text only. |

Because layers merge, a project config **cannot remove** a permissive global rule; it can only add a rule that wins by being later or more specific.

Top-level Config keys (from the published schema): `agent, attachment, autoshare, autoupdate, command, compaction, default_agent, disabled_providers, enabled_providers, enterprise, experimental, formatter, instructions, layout, logLevel, lsp, mcp, mode, model, permission, plugin, provider, reference, references, server, share, shell, skills, small_model, snapshot, subagent_depth, tool_output, tools, username, watcher`.

## What each control actually stops

| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `permission.read` deny patterns | T4 harness deny rule | The `read` tool opening matched paths | `bash` (`cat`, `python -c`), MCP servers reading the filesystem, content already in context |
| `permission.bash` per-command deny patterns | T4 harness deny rule | Literal/glob-matched command strings | Trivial obfuscation (`c""at .env`, `python -c "print(open('.env').read())"`, base64, a wrapper script) |
| `permission.bash: "ask"` or `"deny"` (whole tool) | T4 harness deny rule | All shell execution without a prompt: the only reliable shell posture | Nothing at this layer; still relies on the human answering the prompt |
| `permission.external_directory: {"*": "deny"}` | T4 harness deny rule | Tool access to paths outside the project root | `bash` subprocesses that chdir if `bash` itself is allowed |
| `permission.webfetch` / `websearch` | T4 harness deny rule | The built-in fetch/search tools | Egress via `bash` (`curl`, `wget`), MCP servers, provider API calls |
| `tools: { "<name>": false }` | T4 harness deny rule | Removes the tool from the model entirely: strongest available primitive | Other tools that reach the same capability |
| `permission["*"]` default | T4 harness deny rule | Unlisted/unknown tools, including MCP tools by `additionalProperties` | Anything a later, more specific `allow` rule re-permits |
| `.gitignore` (honoured by ripgrep) | T6 ignore file | Matched paths appearing in `grep` / `glob` **results** | `read` and `bash`: this is search filtering, not access control |
| `watcher.ignore` | T6 ignore file | Directories being file-**monitored** | Any tool access |
| `opencode-ignore` plugin (third-party) | T6 ignore file | gitignore-style access blocking, per the plugin's README | Nothing guaranteed: community code, not vendor-supported |
| `AGENTS.md` / instruction files | T7 instruction file | Nothing; steering only | Any tool call |
| `share: "disabled"` | - (data routing) | Session transcripts syncing to vendor servers and publishing at `opncd.ai/s/<id>` | Provider-side retention |
| `disabled_providers` / `enabled_providers` | - (data routing) | Model traffic going to unapproved providers | Anything else |

**Absent tiers.** OpenCode has **no T1 OS sandbox**, **no T2 egress allowlist**, and **no T3 credential scrub** (contrast Gemini CLI's `security.environmentVariableRedaction`). There is no first-party ignore file. A `plugin` key exists in the schema; treat any repo-committed plugin as arbitrary code execution. **[UNVERIFIED: plugin/hook execution semantics were not confirmed against primary docs.]**

## Rule semantics you must get right

1. **Last matching rule wins**, not deny-wins. This is the opposite of Cursor CLI and Copilot CLI. A broad `allow` placed *after* a `deny` silently re-opens the path. Order the deny entries last within each key.
2. **The default posture is fully open.** From `packages/opencode/src/agent/agent.ts` on `main`:
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
3. **The docs claim ".env files denied by default"; the source says `ask`.** And the guard is on the **`read` tool only**; `bash` defaults to `allow`, so `cat .env` is unprompted on a fresh install.
4. **Absence of a `permission` block is a hard fail, not a neutral.** No block = `"*": "allow"`.
5. Values are exactly `"ask" | "allow" | "deny"`. `permission` may also be a bare string (`"permission": "ask"`), which applies to everything.
6. Permission keys: `read`, `edit` (covers edit/write/patch), `glob`, `grep`, `bash`, `task`, `skill`, `lsp`, `question`, `webfetch`, `websearch`, `external_directory`, `doom_loop`; the schema also carries `list` and `todowrite`.
7. Built-in tool names for the `tools` map: `bash, edit, write, read, grep, glob, lsp, apply_patch, skill, todowrite, webfetch, websearch, question`.
8. Patterns use `*` / `?` wildcards, and `~` / `$HOME` expand.
9. **Agent-level permissions override global ones.** Read `.opencode/agents/*.md` frontmatter, not just `opencode.json`. Built-in agents `plan`, `general`, `explore` layer extra restrictions on top of the defaults.
10. **`mcp.<name>.environment` and `mcp.<name>.headers` accept `{env:VAR_NAME}` and `{file:path}` substitution.** A repo-committed `opencode.json` can therefore pipe local env vars and file contents to an attacker-controlled remote MCP URL. This is the single highest-risk pattern in an OpenCode repo.
11. There is **no documented per-MCP-tool permission gating**. MCP tool names land in the generic `permission` object via schema `additionalProperties`, so a `"*": "ask"` default should catch them. **[UNVERIFIED: exact permission key format for MCP tools.]**
12. `--auto` (`opencode --auto`, `opencode run --auto`) auto-approves anything not *explicitly* denied.
13. `share` accepts `"manual"` (default), `"auto"`, `"disabled"`. `"auto"` publishes every session to a public URL. A separate top-level `autoshare` key also exists.
14. Command-level bash denies are speed bumps. Score `"bash": {"*": "ask"}` or `"bash": "deny"` as the only real boundary.

## Detection checklist

**Repo-visible** (`opencode.json`, `opencode.jsonc`, `.opencode/**`, `AGENTS.md`, `.gitignore`):

| Check | Severity | Where to look |
|---|---|---|
| No `permission` block at all → default `"*": "allow"` | Critical | `opencode.json` root |
| `"permission": "allow"` (string form) anywhere | Critical | `opencode.json`, `.opencode/agents/*.md` frontmatter |
| `mcp.*.headers` / `mcp.*.environment` containing `{env:` or `{file:` alongside a non-localhost `url` | Critical | `opencode.json` → `mcp` |
| `--auto` in scripts, Makefiles, CI workflows, or repo docs | Critical | `.github/workflows/**`, `Makefile`, `package.json` scripts, `README` |
| `permission.bash` missing, `"allow"`, or an object whose `"*"` is `"allow"` | High | `opencode.json` → `permission.bash` |
| `permission.read` lacks **deny** (not merely `ask`) entries for `.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `.netrc`, `.npmrc`, `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`, `~/.kube/**` | High | `opencode.json` → `permission.read` |
| An `allow` rule ordered **after** a `deny` for the same path (last-match-wins re-open) | High | key ordering inside each `permission.*` object |
| `.opencode/agents/*.md` frontmatter `permission` widening the global block | High | each agent file |
| `permission.external_directory` absent or `"ask"` (default) rather than `"deny"` | Medium | `opencode.json` |
| `permission.webfetch` / `websearch` `"allow"` | Medium | `opencode.json` |
| `share` not `"disabled"`, or `autoshare` truthy | Medium | `opencode.json` root |
| Unpinned MCP commands (`npx -y ...`); MCP servers not needed left `enabled: true` | Medium | `opencode.json` → `mcp` |
| `tools` map does not disable `bash`/`write`/`webfetch` in a repo that needs none of them | Low | `opencode.json` → `tools` |
| `disabled_providers` / `enabled_providers` absent (provider set unpinned) | Low | `opencode.json` |
| `.gitignore` missing `.env*`, `*.pem`, `*.key` (helps grep/glob only) | Low | `.gitignore` |

**Must verify out-of-band** (user config; not enforceable from the repo):

| Check | Severity | Where to look |
|---|---|---|
| `~/.config/opencode/opencode.json` sets a permissive `permission` that the repo cannot remove (merge only adds) | High | user config |
| `~/.config/opencode/agents/*.md` widening agent permissions | High | user agents dir |
| Zen gateway in use with a training-eligible free/trial model (e.g. Big Pickle, NVIDIA Nemotron free, "Muse Spark Contributor Free") | High | Zen account settings / `provider` config |
| `experimental.openTelemetry` and any residual outbound telemetry | Info | user config; community reports allege connections persist after disabling and that session titles may be computed remotely. **[UNVERIFIED: issue reports, not vendor confirmation. Egress-test before trusting.]** |

## Hardened baseline

**Repo-committable: `opencode.json` at project root** (complete and exact):

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

Optional additions to the same file (per-agent tightening and outright tool removal):

```json
{
  "agent": {
    "build": {
      "permission": { "bash": { "git commit *": "deny", "git push *": "deny" } }
    }
  },
  "tools": { "write": false, "bash": false }
}
```

**Nothing in this file is ignored from repo scope**: OpenCode's project layer is fully honoured (layer 4). The reverse is the risk: everything here is also writable by a hostile repo. Keys with no repo-scope equivalent at all: there is no ignore file, no sandbox key, and no egress allowlist to set.

**User-level (`~/.config/opencode/opencode.json`)** should carry the same `permission` block so that repos without one still land on a closed posture, plus provider pinning:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "share": "disabled",
  "permission": { "*": "ask", "bash": "ask", "external_directory": { "*": "deny" } },
  "enabled_providers": ["anthropic"]
}
```

Note the merge asymmetry: because a project file sits *above* the user file, this user-level block is a floor for unconfigured repos only; a repo config can still add rules that win.

## Verify at runtime

- Dump the merge inputs in precedence order and diff them: `cat ~/.config/opencode/opencode.json`, `cat ./opencode.json`, `echo "$OPENCODE_CONFIG" "$OPENCODE_CONFIG_CONTENT"`, `ls .opencode/agents/`.
- Confirm no repo config is untracked-but-present or gitignored (a local-only loosening): `git check-ignore -v opencode.json .opencode` and `git status --porcelain opencode.json .opencode`.
- Empirically test the two defaults that matter: ask the agent to read `.env` (expect a deny, not a prompt) and to run `cat .env` / `env` (expect a prompt or deny, not silent output).
- Grep the repo and CI for the bypass flag: `grep -rn -- "--auto" .github Makefile package.json scripts 2>/dev/null`.
- Check the effective share setting by starting a session and confirming no `opncd.ai/s/` URL is emitted.

## Sources

- <https://opencode.ai/docs/config/>
- <https://opencode.ai/docs/permissions/>
- <https://opencode.ai/docs/tools/>
- <https://opencode.ai/docs/agents/>
- <https://opencode.ai/docs/rules/>
- <https://opencode.ai/docs/mcp-servers/>
- <https://opencode.ai/docs/share/>
- <https://opencode.ai/docs/zen/>
- <https://opencode.ai/docs/enterprise/>
- <https://opencode.ai/config.json>
- <https://github.com/anomalyco/opencode/blob/main/packages/opencode/src/agent/agent.ts>
