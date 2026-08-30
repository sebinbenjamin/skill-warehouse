# Hardening Claude Code against secret / environment exfiltration and out-of-repo access

**Researched:** 2026-08-30
**Primary sources:** `code.claude.com/docs` (the `docs.anthropic.com/en/docs/claude-code/*` URLs now 301-redirect to `code.claude.com/docs/en/*`), plus the `anthropics/claude-code` GitHub repo (`examples/settings`, `CHANGELOG.md`).
**Latest release seen in the changelog at time of research:** `2.1.251` (August 28, 2026) — <https://code.claude.com/docs/en/changelog>

> Every factual claim below is followed by the URL it came from. Anything I could not verify against a primary source is explicitly marked **[UNVERIFIED]**.

---

## Summary

Claude Code has five independent enforcement layers. Only two of them are real security boundaries; the rest are best-effort.

| Layer | What it is | Strength |
| :-- | :-- | :-- |
| **Permission rules** (`permissions.allow/ask/deny`) | Claude Code checks the tool call before it runs | Enforced by the harness, not the model. Deny beats everything. **But**: only covers built-in tools + Bash commands Claude Code can parse. Not an OS boundary. |
| **Permission modes** (`default`/`plan`/`acceptEdits`/`auto`/`dontAsk`/`bypassPermissions`) | Baseline of what runs without asking | Policy, not a boundary. `deny` rules still apply in every mode including `bypassPermissions`. |
| **Bash sandbox** (`sandbox.*`) | OS-level (macOS Seatbelt / Linux+WSL2 bubblewrap) filesystem + network isolation for Bash and its children | The only OS-enforced boundary. **Bash only** — does not cover Read/Edit/Write, WebFetch, MCP, or hooks. Not available on native Windows. |
| **Hooks** (`PreToolUse` etc.) | Your own code gates each tool call | Can tighten (deny), cannot loosen past deny rules. Fails **open** on error/timeout/bad path. |
| **Managed settings** | Org policy that user/project settings can't override | The only way to make any of the above non-bypassable by the developer. |

The single most important architectural fact for this threat model:

> "Read and Edit deny rules apply to Claude's built-in file tools and to file commands Claude Code recognizes in Bash, such as `cat`, `head`, `tail`, and `sed`. They don't apply to arbitrary subprocesses that read or write files indirectly, like a Python or Node script that opens files itself. For OS-level enforcement that blocks all processes from accessing a path, enable the sandbox."
> — <https://code.claude.com/docs/en/permissions#read-and-edit>

So a repo-level `.claude/settings.json` with `Read(./.env)` deny rules is **defence against the model doing the obvious thing**, not against an attacker or a prompt injection. Real containment requires `sandbox.filesystem.denyRead` / `sandbox.credentials`, and on Windows that means running inside WSL2 or a container.

---

## 1. settings.json hierarchy

Source: <https://code.claude.com/docs/en/settings>

### The four files (plus managed sources)

| Scope | File | Who it affects | Committed to repo? |
| :-- | :-- | :-- | :-- |
| User | `~/.claude/settings.json` | You, every project on this machine | No |
| Shared project | `.claude/settings.json` | Everyone in the folder; **commit this one** | **Yes** |
| Project local | `.claude/settings.local.json` | You, this project only | No — Claude Code adds `**/.claude/settings.local.json` to your *global git excludes* the first time it writes the file. **If you create it by hand, you must gitignore it yourself.** |
| Managed | `managed-settings.json` (+ `managed-settings.d/*.json`), MDM, or claude.ai console | Everyone the org deploys to | N/A |

On Windows `~/.claude` means `%USERPROFILE%\.claude`; `CLAUDE_CONFIG_DIR` relocates it.
Source: <https://code.claude.com/docs/en/settings#find-or-create-your-settings-files>

### Managed settings file locations

Source: <https://code.claude.com/docs/en/managed-settings#choose-a-delivery-mechanism>

* macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
* Linux and WSL: `/etc/claude-code/managed-settings.json`
* Windows: `C:\Program Files\ClaudeCode\managed-settings.json`
  (the legacy `C:\ProgramData\ClaudeCode\managed-settings.json` is **not** read)
* macOS configuration profile domain: `com.anthropic.claudecode`
* Drop-ins: `managed-settings.d/*.json`, merged after `managed-settings.json` in alphabetical order

### Precedence (highest first)

Source: <https://code.claude.com/docs/en/settings#settings-precedence>

1. **Managed settings** (nothing overrides them, apart from a listed set of security-sensitive exceptions)
2. **Command line arguments** (`--settings`, `--model`, …)
3. **Project local settings** `.claude/settings.local.json`
4. **Shared project settings** `.claude/settings.json`
5. **User settings** `~/.claude/settings.json`

Two critical qualifiers:

* **Lists merge, they don't override.** "When you set the same list key, such as `permissions.allow`, in more than one file, Claude Code combines the lists instead of picking one." So a user-level `deny` list is *added to*, never replaced by, a project one. (<https://code.claude.com/docs/en/settings#lists-merge-instead-of-overriding>)
* **Deny wins across scopes.** "If a tool is denied at any level, no other level can allow it… a user-level deny blocks a project-level allow, because deny rules from any scope are evaluated before allow rules." (<https://code.claude.com/docs/en/permissions#settings-precedence>)

### Workspace trust: what a repo can and cannot do to you

Source: <https://code.claude.com/docs/en/permissions#project-allow-rules-and-workspace-trust>

* `permissions.allow` rules and `permissions.additionalDirectories` from a repo's `.claude/settings.json` apply **only after you accept the trust dialog**.
* **`deny` and `ask` rules apply immediately, trusted or not.** (Good: a repo can restrict itself but not grant itself capability.)
* **Hooks, the `env` block, and helper commands such as `apiKeyHelper` are used even when you've trusted only a *parent* folder, and in `claude -p` / SDK sessions where the trust dialog never appears.** This is a real exposure surface for untrusted repos.
* `claude -p` and SDK sessions **never** show the trust dialog and count as "accepted" for the git check.

Recommended posture before running `claude -p` in a repo you didn't write (verbatim from the docs):

* `--setting-sources user` (or SDK `settingSources` without `project`) — reads neither the project's settings files nor its `.mcp.json`
* `--bare` — reads no hooks, skills, custom commands, subagents, plugins, or `.mcp.json` servers from the project
* `--settings '{"disableAllHooks": true}'` — note the docs explicitly warn that setting `disableAllHooks` in *user* settings alone is not enough, because project settings outrank it
* `disabledMcpjsonServers` entries to reject `.mcp.json` servers by name

### Cloud sessions read only some files

Source: <https://code.claude.com/docs/en/settings#settings-in-cloud-sessions>

* `.claude/settings.json` — **read** (it's in the clone)
* `~/.claude/settings.json` and `.claude/settings.local.json` — **not read**
* Managed: only *server*-managed settings reach a cloud session; a local `managed-settings.json` or MDM profile does not.

Consequence for a hardening scanner: for cloud/CI, the committed `.claude/settings.json` is the *only* local lever.

---

## 2. Permission rule syntax

Primary source: <https://code.claude.com/docs/en/permissions>
Settings-key reference: <https://code.claude.com/docs/en/settings-reference#permission-settings>

### Evaluation order

> "Rules are evaluated in order: deny, then ask, then allow. The first match in that order determines the outcome, and rule specificity doesn't change the order."
> — <https://code.claude.com/docs/en/permissions#manage-permissions>

**Yes, deny beats allow — unconditionally, and across every scope.** A broad deny like `Bash(aws *)` blocks calls that also match a narrower allow like `Bash(aws s3 ls)`; "a deny rule can't carry allowlist exceptions." The same precedence applies between ask and allow.

Also: a **bare tool name** in `deny` (e.g. `"Bash"`, or the glob `"mcp__*"`) *removes the tool from Claude's context entirely* — Claude never sees it. A scoped rule (`Bash(rm *)`) leaves the tool present and blocks matching calls. The only exception is `EndConversation`, which a deny/ask rule can't remove while any other tool remains.

### Rule shapes

```
Tool                      # all uses of the tool
Tool(specifier)           # scoped
Tool(param:value)         # deny/ask only - match a top-level input parameter
```

| Rule | Matches |
| :-- | :-- |
| `Bash` / `Bash(*)` | every Bash command (as deny: removes the tool) |
| `Bash(npm run build)` | that exact command |
| `Bash(npm run *)` | `npm run build`, `npm run test --watch`, and bare `npm run` |
| `Bash(curl:*)` | equivalent to `Bash(curl *)` — the `:*` suffix is only recognised **at the end** of a pattern |
| `Read(./.env)` | the `.env` file in the current directory |
| `WebFetch(domain:example.com)` | fetches to that host |
| `mcp__puppeteer` | any tool from the `puppeteer` server |
| `mcp__puppeteer__*` | same |
| `mcp__*` | (deny/ask only) every MCP tool from every server |
| `Agent(Explore)` | the Explore subagent |
| `Agent(model:opus)` | Agent calls requesting the Opus tier (parameter match) |
| `Bash(run_in_background:true)` | Bash calls that background themselves |
| `Cd(~/code/**)` | `/cd` targets under `~/code` |

Parameter-matching caveats (<https://code.claude.com/docs/en/permissions#match-by-input-parameter>): you **cannot** match a tool's primary content field — `command` for Bash/PowerShell, `file_path` for Read/Edit/Write, `path` for Grep/Glob, `notebook_path` for NotebookEdit, `url` for WebFetch. `Bash(command:rm *)` is ignored with a startup warning because a compound command would bypass it. MCP parameter rules must be passed via `--disallowedTools`; an `mcp__` rule *with parentheses* in a settings file is **silently skipped** (it is listed in the invalid-settings dialog and in `claude doctor` output).

Allow-rule tool-name globs are restricted: `"*"`, `"B*"`, `"mcp__*"` in `allow` are skipped with a warning and auto-approve nothing. Only `mcp__<literal-server>__<glob>` is accepted in `allow`.

### Path pattern resolution for `Read` / `Edit`

Source: <https://code.claude.com/docs/en/permissions#read-and-edit>

Read/Edit rules use **gitignore pattern syntax** with four anchor forms:

| Pattern | Meaning | Example resolves to |
| :-- | :-- | :-- |
| `//path` | **absolute** from filesystem root | `Read(//Users/alice/secrets/**)` -> `/Users/alice/secrets/**` |
| `~/path` | home directory | `Read(~/Documents/*.pdf)` |
| `/path` | relative to the **settings source**, *not* the filesystem root | see table below |
| `path` or `./path` | relative to current directory | `Read(*.env)` -> `<cwd>/*.env` |

> **Trap:** "A pattern like `/Users/alice/file` isn't an absolute path. The single leading slash anchors at the settings source, not the filesystem root. Use `//Users/alice/file` for absolute paths."

Where `/path` anchors:

| Rule defined in | `/path` resolves to |
| :-- | :-- |
| `.claude/settings.json` | `<primary working directory>/path` |
| `.claude/settings.local.json` | `<primary working directory>/path` |
| `~/.claude/settings.json` | **`~/.claude/path`** (not `~/path`, not the project) |
| `--settings <file>` | `<directory of file>/path` |
| CLI flags / session rules | `<primary working directory>/path` |

> "A deny rule such as `Read(/secrets/**)` in user settings blocks `~/.claude/secrets/**`, not a `secrets` directory in your project. To write a rule in user settings that applies inside every project, use a `//` absolute path or a `~/` home-relative path instead."

**Windows:** paths are normalised to POSIX before matching — `C:\Users\alice` becomes `/c/Users/alice`. Use `//c/**/.env` to match `.env` anywhere on that drive, `//**/.env` to match across all drives.

Depth semantics (subtle, and it matters for rules like `Read(**/secrets/**)`):

* Bare filenames follow gitignore semantics and match at **any depth**: `Read(.env)` is equivalent to `Read(**/.env)`.
* A single-segment directory pattern like `src/**` behaves **differently by rule type**:
  * **allow**: matches only `<cwd>/src` and files under it
  * **deny/ask**: matches a directory named `src` at **any depth** under cwd
* Every other shape matches at the same depth in all rule types: `/src/**` only at its anchor, `**/src/**` at any depth.

| Deny rule | Blocks | Does not block |
| :-- | :-- | :-- |
| `Read(.env)` or `Read(**/.env)` | any `.env` at or under the current directory | `.env` in a parent directory or another project |
| `Read(//**/.env)` | any `.env` anywhere on the filesystem | nothing |

### Symlinks

Source: <https://code.claude.com/docs/en/permissions#read-and-edit>

Permission checks evaluate **both** the symlink path and its resolved target:

* **allow** rules require *both* to match (a symlink inside an allowed directory pointing outside it still prompts)
* **deny** rules fire if *either* matches

Docs example: with `Read(./project/**)` allowed and `Read(~/.ssh/**)` denied, a symlink `./project/key` pointing to `~/.ssh/id_rsa` is blocked.

Two symlink bypasses were only fixed in **2.1.251 (Aug 28 2026)** — see [Known gaps](#known-gaps--caveats).

### Does a `Read` deny also block Grep, Glob, Edit, Write, and Bash `cat`?

Sources: <https://code.claude.com/docs/en/permissions#read-and-edit>, <https://code.claude.com/docs/en/settings-reference#permissions-deny>

| Surface | Covered by a `Read(...)` deny rule? |
| :-- | :-- |
| Read tool | Yes |
| Grep, Glob | Yes — best-effort. "Grep and Glob search the directory the `path` argument resolves to. Claude Code applies `Read` deny rules to that directory." Matching files are also excluded from file discovery and search results. |
| `@file` mentions in your prompt | Yes (best-effort) |
| IDE selection / open-file context shared by the built-in IDE MCP server | Yes (best-effort) |
| Edit tool | **Yes**, requires v2.1.208+ |
| Write tool (including creating a new file at that path) | **Yes**, requires v2.1.228+ |
| NotebookEdit | **No** — add an explicit `Edit(...)` deny rule |
| Bash `cat`, `head`, `tail`, `sed` | Yes — Claude Code recognises these file commands |
| Bash: arbitrary subprocess (`python -c "print(open('.env').read())"`, node, ruby, a build script) | **No** |
| MCP server tools that read files | **No** — deny `mcp__*` or the specific server |

Rules written against the wrong tool are accepted but never consulted, with a startup warning: use `Edit(docs/**)` in place of `Write(docs/**)`, `NotebookEdit(docs/**)` or `MultiEdit(docs/**)`, and `Read(docs/**)` in place of `Glob(docs/**)`. (A tool-name deny rule with no path, such as a bare `Write` deny, is matched at the tool level and is fine.)

### Bash rule matching internals (why argument-scoped Bash rules are weak)

Source: <https://code.claude.com/docs/en/permissions#bash>

* **Compound commands are split.** Recognised separators: `&&`, `||`, `;`, `|`, `|&`, `&`, and newlines. A rule must match each subcommand independently, so `Bash(safe-cmd *)` does not authorise `safe-cmd && other-cmd`.
* **Wrappers are stripped before matching**: `timeout`, `time`, `nice`, `nohup`, `stdbuf`, the shell builtins `command` and `builtin`, zsh's `noglob`, and bare `xargs` (only when flagless). Leading assignments of known-safe env vars are stripped for allow rules; **deny/ask rules match past any leading assignment**, so `Bash(rm *)` in deny still catches `FOO=bar rm -rf tmp/`.
* **Environment runners are NOT stripped and are NOT configurable**: `direnv exec`, `devbox run`, `mise exec`, `npx`, `docker exec`. Therefore `Bash(devbox run *)` as an allow rule matches `devbox run rm -rf .`.
* **Exec wrappers can't be prefix-approved**: `watch`, `setsid`, `ionice`, `flock`, and `find` with `-exec`/`-delete` always prompt in Manual mode.
* **The built-in read-only command set runs without a prompt in every mode and is not configurable**: `ls`, `cat`, `echo`, `pwd`, `head`, `tail`, `grep`, `find`, `wc`, `which`, `diff`, `stat`, `du`, `cd`, and read-only forms of `git`. "The set is not configurable; to require a prompt for one of these commands, add an `ask` or `deny` rule for it." Note that `cat` is in this set — what stops `cat .env` is the `Read` deny rule, not the Bash permission flow.
* **Output redirections are checked as file writes** (`>`, `>>`, `2>`) against Edit allow/deny rules, protected paths, and the working directories. `/dev/null` is exempt. A target that starts with `~` or contains a glob character needs approval.
* Commands longer than 10,000 characters always prompt; commands Claude Code can't parse prompt.

The docs' own warning, verbatim in substance:

> "Bash permission patterns that try to constrain command arguments are fragile. For example, `Bash(curl http://github.com/ *)` intends to restrict curl to GitHub URLs, but won't match variations like: options before URL … different protocol … redirects … variables: `URL=http://github.com && curl $URL` … extra spaces."
>
> Recommended instead: deny `curl`/`wget` and use `WebFetch(domain:…)`; use PreToolUse hooks to validate URLs; CLAUDE.md guidance shapes what Claude tries but doesn't enforce a boundary. **"Note that using WebFetch alone doesn't prevent network access. If Bash is allowed, Claude can still use `curl`, `wget`, or other tools to reach any URL."**
> — <https://code.claude.com/docs/en/permissions#read-only-commands>

### WebFetch rules

Source: <https://code.claude.com/docs/en/permissions#webfetch>

* `WebFetch(domain:example.com)` — exact host, case-insensitive, trailing `.` stripped
* `WebFetch(domain:*.example.com)` — any subdomain at any depth, but **not** `example.com` itself
* `WebFetch(domain:*)` — every domain, **and** feeds the sandbox allowed/denied domain list
* A **bare** `WebFetch` rule covers every URL but does **not** touch the sandbox domain lists

| Rule | In `allow` | In `deny` |
| :-- | :-- | :-- |
| `WebFetch` | fetches without prompting; sandbox host list unchanged | the WebFetch tool is removed from Claude; sandbox host list unchanged |
| `WebFetch(domain:*)` | fetches without prompting **and** sandboxed commands can reach any host | each fetch refused **and** sandboxed commands can reach no host |

A wildcard in any position other than a leading `*.` matches only the text between two dots: `example.*` matches `example.org` but not `example.evil.com`. Wildcards in WebFetch rules require v2.1.172+ to match fetches.

### PowerShell rules

Source: <https://code.claude.com/docs/en/permissions#powershell>. Same shape as Bash. Aliases are canonicalised (a `Get-ChildItem` rule also matches `gci`, `ls`, `dir`), matching is case-insensitive, and the AST is parsed so `|`, `;`, and (PS7+) `&&`/`||` split compound commands. Every subcommand must match for a compound command to be allowed.

### `Cd` rules (restrict `/cd`)

Source: <https://code.claude.com/docs/en/permissions#cd>. `Cd` is not model-invocable — it only gates the human's `/cd` command. A bare `Cd` deny disables `/cd`. Adding **any** `Cd` allow rule switches `/cd` to allowlist mode. Path patterns use the same `//`, `~/`, `/` anchors but are matched against the whole directory path rather than gitignore-style: `*` matches exactly one segment, `**` crosses segments, and a trailing `/**` also matches its named root. Deny rules check every spelling of the target including each symlink hop.

### Hooks vs rules

Source: <https://code.claude.com/docs/en/permissions#extend-permissions-with-hooks>

* PreToolUse hooks run **before** the permission prompt, for every tool except `EndConversation`.
* A hook `"allow"` does **not** bypass deny or ask rules — those are still evaluated.
* A hook that exits **2 blocks the call before permission rules are evaluated**, so it overrides allow rules.
* Documented pattern: put `"Bash"` in `allow` and register a PreToolUse hook that rejects the specific commands you want blocked.
---

## 3. `additionalDirectories`, `defaultMode`, and the locks

### `permissions.additionalDirectories`

Source: <https://code.claude.com/docs/en/settings-reference#permissions-additionaldirectories>, <https://code.claude.com/docs/en/permissions#working-directories>

```json
{
  "permissions": {
    "additionalDirectories": ["../docs/"]
  }
}
```

* By default Claude has file access to the directory it was launched in (the session's **primary working directory**) and its subdirectories only.
* Extend with `--add-dir <path>` (startup), `/add-dir` (session), or this key (persistent).
* Files in additional directories "become readable without prompts, and file editing permissions follow the current permission mode."
* **Entries in a project's `.claude/settings.json` take effect only after the workspace trust dialog is accepted.**
* **Important distinction:** directories from the *settings key* grant file access only. Directories from `--add-dir`/`/add-dir` additionally load `.claude/skills/`, `.claude/commands/`, `.claude/agents/`, and the `enabledPlugins`/`extraKnownMarketplaces` settings keys from that directory — i.e. `--add-dir` is a bigger trust grant than the settings key.
  (<https://code.claude.com/docs/en/permissions#additional-directories-grant-file-access-not-configuration>)
* `/cd <path>` moves the primary working directory and **applies the new directory's project settings, hooks, `.mcp.json` servers, plugins, skills, subagents and `env` values** (v2.1.246+). Restrict with `Cd` rules.

For a hardened repo config, do **not** add `additionalDirectories`. If you must, use narrow paths.

### `permissions.defaultMode`

Source: <https://code.claude.com/docs/en/settings-reference#permissions-defaultmode>, <https://code.claude.com/docs/en/permission-modes>

| Value | What runs without asking |
| :-- | :-- |
| `"default"` (alias `"manual"`, v2.1.200+) | reads only |
| `"acceptEdits"` | reads, file edits, and `mkdir` `touch` `rm` `rmdir` `mv` `cp` `sed` inside the working dir / additionalDirectories |
| `"plan"` | reads; plus classifier-approved commands when auto mode is available |
| `"auto"` | everything, with a classifier model reviewing actions |
| `"dontAsk"` | only pre-approved tools; everything that would prompt is **auto-denied** |
| `"bypassPermissions"` | everything |

Mode selection order for a new terminal session (<https://code.claude.com/docs/en/permission-modes#which-mode-a-session-starts-in>):

1. `--permission-mode` flag, or `--dangerously-skip-permissions`
2. `permissions.defaultMode` from a settings file
3. the built-in default

**The built-in default is now `auto` on Pro, Max, and Team plans in a terminal or the VS Code extension** (requires v2.1.228+ on macOS/Linux/WSL, v2.1.233+ on native Windows). It is `default` for: `claude -p` / the Agent SDK, Enterprise plans, Console API keys, Bedrock / Google Agent Platform / Foundry / Claude Platform on AWS / signed-in Claude apps gateway, any settings file that sets `disableAutoMode`, and when feature-flag fetching is off.

Two gotchas:

* **`"auto"` does not take effect from `.claude/settings.json` or `.claude/settings.local.json`** — it must be in `~/.claude/settings.json` or managed settings. If a project file sets it, Claude Code falls back to the built-in default and ignores a `defaultMode` in user settings.
* Conversations started by the **VS Code extension never read project settings** for the starting permission mode; it reads `claudeCode.initialPermissionMode`, then the last mode you picked, then `permissions.defaultMode` from managed/user settings.

To force manual review everywhere on a machine:

```json
{
  "permissions": {
    "defaultMode": "default"
  }
}
```

### `permissions.disableBypassPermissionsMode`

Source: <https://code.claude.com/docs/en/settings-reference#permissions-disablebypasspermissionsmode>

```json
{
  "permissions": {
    "disableBypassPermissionsMode": "disable"
  }
}
```

* Type is the literal string `"disable"` (not a boolean).
* **Scope: any file.** "A user can set it in their own settings to lock themselves out of bypass mode." Typically deployed in managed settings.
* Rejects `--dangerously-skip-permissions`, and **ignores a subagent definition's `permissionMode: bypassPermissions`** (v2.1.223+; before that the frontmatter mode still applied).
* Takes precedence over the CLI flag.

### `disableAutoMode` / `permissions.disableAutoMode`

Source: <https://code.claude.com/docs/en/settings-reference#disableautomode>

```json
{ "disableAutoMode": "disable" }
```

Removes `auto` from the Shift+Tab cycle; a session started with `--permission-mode auto` starts in Manual instead; any session that would start in auto starts in `default`. Accepted at the top level or nested under `permissions`. From v2.1.251, a running auto-mode session leaves auto mode when this arrives from an admin-deployed source.

### The managed-only locks

These are the keys that actually make a policy non-bypassable. All are **`Managed` scope only** unless noted.

| Key | Effect | Source |
| :-- | :-- | :-- |
| `allowManagedPermissionRulesOnly: true` | Managed settings become the **only** source of allow/ask/deny rules. Ignores rules from user/project/local/`--settings`, ignores `--allowedTools`, hides "always allow" choices in prompts, and stops saving new rules. | <https://code.claude.com/docs/en/settings-reference#allowmanagedpermissionrulesonly> |
| `allowManagedHooksOnly: true` | Blocks user, project, local, and plugin hooks; also narrows `statusLine`, `fileSuggestion`, `subagentStatusLine` to managed settings and disables plugin `command` sources and marketplace `headersHelper` commands. | <https://code.claude.com/docs/en/settings-reference#allowmanagedhooksonly> |
| `allowManagedMcpServersOnly: true` | Only the managed `allowedMcpServers` allowlist applies (denylists still merge from every file). | <https://code.claude.com/docs/en/settings-reference#allowmanagedmcpserversonly> |
| `sandbox.filesystem.allowManagedReadPathsOnly: true` | Only managed `allowRead` entries are honoured, so developers can't widen sandbox read access. | <https://code.claude.com/docs/en/sandboxing#keep-developers-from-widening-the-policy> |
| `sandbox.network.allowManagedDomainsOnly: true` | Only managed `allowedDomains` and managed `WebFetch(domain:…)` allow rules count; non-allowed domains are blocked instead of prompting. | same |
| `strictKnownMarketplaces` | Restricts plugin marketplaces (`[]` blocks all). | <https://code.claude.com/docs/en/settings-reference#strictknownmarketplaces> |
| `enforceAvailableModels` + `availableModels` | Restrict model selection. | <https://code.claude.com/docs/en/settings-reference#availablemodels> |
| `disableSideloadFlags` | Enterprise/managed. | <https://code.claude.com/docs/en/settings-reference#disablesideloadflags> |

Notable **absence of a lock**: `sandbox.excludedCommands` has **no** managed-only lock — "a developer can always append entries that run additional commands outside the sandbox. Keep the managed list narrow." (<https://code.claude.com/docs/en/sandboxing#keep-developers-from-widening-the-policy>)

### Security-sensitive keys where a *stricter* lower-scope value wins over managed

Source: <https://code.claude.com/docs/en/settings#exceptions-to-managed-settings-precedence>

`disableClaudeAiConnectors: true`, `enableArtifact: false` / `disableArtifact: true`, `isolatePeerMachines: true`, `remoteControlAtStartup: false` (project/local only), a stricter `crossSessionInbound`, `useAutoModeDuringPlan: false`, `syncClaudeAiSkills: false`.

### Protected paths (never auto-approved for writes, in any mode except bypass)

Source: <https://code.claude.com/docs/en/permission-modes#protected-paths>

Directories: `.git`, `.config/git`, `.vscode`, `.idea`, `.husky`, `.cargo`, `.devcontainer`, `.yarn`, `.mvn`, `.claude` (except `.claude/worktrees`).
Files: `.gitconfig`, `.gitmodules`, the shell rc family (`.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.zshenv`, `.profile`, `.envrc`, …), `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `.pnp.cjs`, `.pnpmfile.cjs`, `bunfig.toml`, `.bazelrc`, `.pre-commit-config.yaml`, `lefthook.*`, `gradle-wrapper.properties`, `maven-wrapper.properties`, `.devcontainer.json`, `.ripgreprc`, `pyrightconfig.json`, `.mcp.json`, `.claude.json`.

Crucially: **`permissions.allow` rules do not pre-approve protected-path writes** — the safety check runs before allow rules are evaluated. In `dontAsk` mode protected-path writes are **denied**; in `bypassPermissions` they are **allowed**.

### Critical paths (`rm`/`rmdir` circuit breaker)

Source: <https://code.claude.com/docs/en/permission-modes#critical-paths>. No allow rule and no PreToolUse `"allow"` can approve an `rm`/`rmdir` targeting the filesystem root, a top-level directory, your home directory, a Windows drive root, your working directory or its parents, or a glob under an additional working directory. Command/process substitution does not evade the check. In `dontAsk` mode these are denied; in `bypassPermissions` you are still asked.

### `--restricted` (new in v2.1.248, Aug 27 2026)

Source: <https://code.claude.com/docs/en/cli-reference> ("`--restricted`"), <https://code.claude.com/docs/en/changelog>

`claude --restricted` (or `CLAUDE_CODE_RESTRICTED=1`, which is ignored from a settings `env` block):

* removes the built-in tools that run commands or code, **and WebFetch**, unless you name them individually in `--tools` (the `default` preset does not count)
* confines the built-in file tools to the working directories
* **loads only managed settings and `--settings`** — ignores user, project, and local settings files
* refuses `bypassPermissions`, and refuses to create cloud sessions
* the auto-mode classifier can't approve protected-path writes in a restricted session

This is the closest thing to a "run this repo's agent with nothing of mine attached" switch.
---

## 4. Sandboxing (the only OS-enforced layer)

Primary source: <https://code.claude.com/docs/en/sandboxing>
Settings reference: <https://code.claude.com/docs/en/settings-reference#sandbox-settings>

### Platform support

> "The sandbox is built into Claude Code and runs on macOS, Linux, and WSL2. **Native Windows is not supported.** On Windows, run Claude Code inside a WSL2 distribution."

* macOS: **Seatbelt** (nothing to install)
* Linux and WSL2: **bubblewrap** + **socat** (`sudo apt-get install bubblewrap socat`), plus an *optional* seccomp filter (`npm install -g @anthropic-ai/sandbox-runtime`) that adds Unix-domain-socket blocking. Ripgrep is bundled with the native binary.
* WSL1 is not supported.
* Ubuntu 24.04+ needs an AppArmor profile for `bwrap` when `sysctl kernel.apparmor_restrict_unprivileged_userns` returns `1`.
* Same primitives are available standalone as `@anthropic-ai/sandbox-runtime` to wrap the whole Claude Code process (<https://code.claude.com/docs/en/sandbox-environments#sandbox-runtime>).

**Failure mode by default is open:** "if the sandbox cannot start because dependencies are missing or the platform is unsupported, Claude Code shows a warning and runs commands without sandboxing." Set `sandbox.failIfUnavailable: true` to make it a hard failure.

### Scope: what the sandbox does and does not cover

Source: <https://code.claude.com/docs/en/sandboxing#scope>

| Covered | Not covered |
| :-- | :-- |
| Bash commands **and all their child processes** | Read / Edit / Write tools (permission system only) |
| Subagents' Bash commands (same config as the parent) | WebFetch / WebSearch (in-process) |
| | MCP servers and hooks |
| | Computer use (runs on your real desktop) |
| | Environment variables (inherited unless `sandbox.credentials` or `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`) |

### Default boundaries

Source: <https://code.claude.com/docs/en/sandboxing#filesystem-isolation>

* **Write:** working directory + `--add-dir` directories + the session temp directory (`$TMPDIR`) only.
* **Read: the entire computer**, except paths you deny. The docs are explicit: *"this default still allows reading credential files such as `~/.aws/credentials` and `~/.ssh/`."*
* **Network: no domains pre-allowed.** The first time a command needs a host, Claude Code prompts (or sends it to the auto-mode classifier). "Yes, and don't ask again" writes a `WebFetch(domain:...)` allow rule to local settings.
* Blocked: modifying files outside the writable set, including `~/.bashrc` and `/bin/`.
* Git worktrees: writes to the main repo's shared `.git` are allowed so `git commit` works, but `hooks/` and `config` inside it stay denied.

### Filesystem configuration

Path prefixes here **differ from permission rules**: `/tmp/build` is absolute, `~/.kube` is home-relative, and `./output` or bare `output` is relative to the project root for project settings or to `~/.claude` for user settings.
Source: <https://code.claude.com/docs/en/sandboxing#configure-sandboxing>

```json
{
  "sandbox": {
    "enabled": true,
    "filesystem": {
      "allowWrite": ["~/.kube", "/tmp/build"],
      "denyRead": ["~/"],
      "allowRead": ["."]
    }
  }
}
```

Overlap resolution: "the more specific path wins."

| Rules | Result |
| :-- | :-- |
| `"denyRead": ["~/"]` + `"allowRead": ["~/projects"]` | `~/projects` readable, rest of home blocked |
| `"allowRead": ["~/"]` + `"denyRead": ["~/.env"]` | `~/.env` blocked, rest of home readable — "the deny holds inside a wider allow, so a broad allow can't silently re-expose a secret" |
| `"allowRead": ["~/"]` + `"denyRead": ["~/**/.env"]` | every `.env` under home blocked; wildcard deny holds inside a wider allow |

Permission rules feed the same lists: `Edit` allow/deny -> `allowWrite`/`denyWrite`, `Read` deny -> `denyRead`, `WebFetch(domain:...)` allow/deny -> the network domain lists. Arrays **merge across every settings scope**.

`sandbox.filesystem.disabled: true` turns off the filesystem layer while keeping network isolation. It is honoured **only from user settings, managed settings, and `--settings`** — "Project settings in `.claude/settings.json` and `.claude/settings.local.json` can't [set it], so a checked-out project can't switch filesystem isolation off." When managed settings configure `sandbox.filesystem` at all, or list any `credentials.files` entry with `"mode": "deny"`, only managed settings can set it. `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` makes it ignored from every source.

### Protecting credentials from sandboxed commands

Source: <https://code.claude.com/docs/en/sandboxing#protect-credentials> (requires v2.1.187+)

> **"There is no built-in credential deny list, so only the files and variables you list are restricted."**

```json
{
  "sandbox": {
    "enabled": true,
    "credentials": {
      "files": [
        { "path": "~/.aws/credentials", "mode": "deny" },
        { "path": "~/.ssh", "mode": "deny" }
      ],
      "envVars": [
        { "name": "GITHUB_TOKEN", "mode": "deny" },
        { "name": "NPM_TOKEN", "mode": "deny" }
      ]
    }
  }
}
```

* `"mode": "deny"` on a file = a `denyRead` inside the sandbox (part of the filesystem layer, so `filesystem.disabled` lifts it). `"mode": "deny"` on an env var **unsets it before each sandboxed command** and is independent of the filesystem layer.
* `"mode": "mask"` (v2.1.199+ for env vars, v2.1.221+ for files) replaces the value with a per-session sentinel and has the sandbox proxy substitute the real value on egress to `injectHosts`. It requires `network.tlsTerminate` and is **only honoured from user settings, managed settings, and `--settings`** — repository settings are ignored for `mask`, `tlsTerminate`, `allowPlaintextInject`, `awsPairs`, and `sigv4`.
* On macOS, a file `mask` behaves like `deny` (the file is unreadable), but the block holds even with filesystem isolation off.
* `deny` entries merge from every scope and no scope can remove one added by another.
* `credentials.awsPairs` / `credentials.sigv4` handle SigV4 re-signing (v2.1.224+).

### Network isolation

Source: <https://code.claude.com/docs/en/sandboxing#network-isolation>

```json
{
  "sandbox": {
    "network": {
      "allowedDomains": ["registry.npmjs.org", "*.github.com"],
      "deniedDomains": ["uploads.github.com"],
      "strictAllowlist": true,
      "allowAllUnixSockets": false,
      "allowUnixSockets": [],
      "allowLocalBinding": false,
      "allowMachLookup": [],
      "httpProxyPort": null,
      "socksProxyPort": null,
      "tlsTerminate": {}
    }
  }
}
```

* `strictAllowlist: true` (v2.1.219+) denies any host outside the allowlist instead of prompting. **Honoured only from user, managed, or `--settings`; setting it in a repository's `.claude/settings.json` or `.claude/settings.local.json` has no effect.** It applies to sandboxed commands only; in-process WebFetch still follows permission rules.
* `allowManagedDomainsOnly` (managed) blocks non-allowed domains automatically and honours only managed domain entries.
* `allowUnixSockets` is **macOS only**; on Linux/WSL2 use `allowAllUnixSockets` (default `false`) and note the seccomp filter must be installed for Unix sockets to be blocked at all. On WSL2, `true` also reopens the interop socket that launches `cmd.exe`/`powershell.exe`.
* IPv6 literals must be bracketed in domain lists: `"[::1]"`, `"[::1]:443"` (v2.1.229+); `injectHosts` uses the bare compressed form `"::1"`.
* Default proxy **does not terminate or inspect TLS**. `network.tlsTerminate` is experimental (v2.1.199+) and exists for credential masking, not content filtering.

Explicit exfiltration warning from the docs:

> "Allowing broad domains such as `github.com` can create paths for data exfiltration. Because the proxy makes its allow decision from the client-supplied hostname without inspecting TLS, code running inside the sandbox can potentially use domain fronting or similar techniques to reach hosts outside the allowlist."

### Sandbox modes and the escape hatch

Source: <https://code.claude.com/docs/en/sandboxing#sandbox-modes>

* **Auto-allow mode** (`autoAllowBashIfSandboxed: true`, the **default**): sandboxed commands run with no prompt. "Bash commands that modify files within the sandbox boundaries execute without prompting, even in Manual mode, where the file edit tools would prompt." Deny rules, content-scoped ask rules like `Bash(git push *)`, and critical-path `rm` checks still apply; a bare `Bash` ask rule is *skipped* for sandboxed commands (except in plan mode, v2.1.212+).
* **Regular permissions mode** (`autoAllowBashIfSandboxed: false`): everything goes through the normal permission flow.
* **`dangerouslyDisableSandbox` escape hatch:** when the sandbox blocks a command, Claude may retry it unsandboxed; that retry goes through the normal permission flow (or the classifier in auto mode). Turn it off with `"allowUnsandboxedCommands": false` (shown as **Strict sandbox mode** in `/sandbox`). To be prompted on every retry even in auto mode, add an ask rule for `Bash(dangerouslyDisableSandbox:true)`.
* `sandbox.excludedCommands` runs listed commands **outside** the sandbox entirely. "Exclusion is a convenience, not a security boundary."

### Sandbox protected paths

Source: <https://code.claude.com/docs/en/sandboxing#protected-paths>. Even inside writable directories the sandbox denies writes to: `.claude` settings files and `.claude/skills|agents|commands|hooks`, `.mcp.json`, `.claude/workflows`, `.claude/scheduled_tasks.json` (in cwd and above); shell startup files, `.gitconfig`, `.vscode`, `.idea`, and `.git/hooks|config` (in cwd); files that would turn cwd into a bare git repo; and most of `~/.claude` plus `~/.claude.json` and `.credentials.json`. **There is no way to exempt these** — an `allowWrite` entry or `Edit` allow rule does not lift the protection; only `filesystem.disabled` does.

### Enforcing it for an organisation

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false
  }
}
```

Source: <https://code.claude.com/docs/en/sandboxing#enforce-sandboxing-with-managed-settings>. The docs add: "Add `sandbox.credentials` entries for credential directories such as `~/.aws` and `~/.ssh` and for secret environment variables, since the default read policy still allows them," and "The sandbox does not run on native Windows, so if your fleet includes Windows hosts, scope this configuration to macOS and Linux or have those users run Claude Code inside WSL2 or a container."

### Stated security limitations

Source: <https://code.claude.com/docs/en/sandboxing#security-limitations>

* No TLS inspection by default -> domain fronting is possible.
* `allowUnixSockets` can grant host access (e.g. `/var/run/docker.sock`).
* Broad `allowWrite` into `$PATH` directories or shell rc files enables privilege escalation.
* `enableWeakerNestedSandbox` (for Docker/no-userns hosts) "considerably weakens security."
* `allowAppleEvents: true` on macOS "removes code-execution isolation" — sandboxed commands can launch other applications unsandboxed with no prompt. Only honoured from user/managed/CLI settings; project settings can't enable it.
* `--dangerously-skip-permissions` is blocked when running as root or via sudo on Linux/macOS (skipped inside a recognised sandbox).

And the summary warning:

> "Effective sandboxing requires both filesystem and network isolation. Without network isolation, a compromised agent could exfiltrate sensitive files like SSH keys. Without filesystem isolation … a compromised agent could backdoor system resources to gain network access."

---

## 5. Hooks

Primary source: <https://code.claude.com/docs/en/hooks>
Guide with worked examples: <https://code.claude.com/docs/en/hooks-guide>

### Full hook event list

From the matcher table at <https://code.claude.com/docs/en/hooks#matcher-patterns> and the event sections:

`SessionStart`, `Setup`, `InstructionsLoaded`, `UserPromptSubmit`, `UserPromptExpansion`, `MessageDisplay`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PermissionDenied`, `Notification`, `SubagentStart`, `SubagentStop`, `TaskCreated`, `TaskCompleted`, `Stop`, `StopFailure`, `TeammateIdle`, `ConfigChange`, `CwdChanged`, `DirectoryAdded`, `FileChanged`, `WorktreeCreate`, `WorktreeRemove`, `PreCompact`, `PostCompact`, `PreModelSwitch`, `PostModelSwitch`, `SessionEnd`, `Elicitation`, `ElicitationResult`.

(`PreModelSwitch`/`PostModelSwitch` were added in 2.1.251.)

### Configuration shape

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/protect-files.sh",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Handler types: `command`, `http`, `mcp_tool`, `prompt`, `agent`. Handler fields include `if` (a single permission-rule string like `"Bash(git *)"` or `"Edit(*.ts)"`), `timeout`, `statusMessage`, `once`, `async`, `asyncRewake`, `shell` (`"bash"` or `"powershell"`), and `args` (exec form — no shell).

Matcher semantics (<https://code.claude.com/docs/en/hooks#matcher-patterns>): `"*"`/`""`/omitted = all; a string of only letters/digits/`_`/`-`/spaces/`,`/`|` is an exact match or `|`/`,`-separated list of exact matches; anything else is an **unanchored JavaScript regex**, so `Edit.*` also matches `NotebookEdit` — anchor with `^Edit$` when you need exactness. MCP tools need `.*`: `mcp__memory__.*`, `mcp__.*__write.*`; a bare `mcp__memory` matches nothing.

Hook locations and scope (<https://code.claude.com/docs/en/hooks#hook-locations>): `~/.claude/settings.json`, `.claude/settings.json` (committable), `.claude/settings.local.json`, managed policy settings, plugin `hooks/hooks.json`, skill frontmatter, subagent frontmatter. Hooks **merge** across levels; `disableAllHooks` outside managed settings cannot disable managed hooks. `allowedHttpHookUrls` and `httpHookAllowedEnvVars` constrain HTTP hooks at every level.

### Exit code semantics

Source: <https://code.claude.com/docs/en/hooks#exit-code-output>

| Exit code | Meaning |
| :-- | :-- |
| `0` | success. Stdout is parsed as JSON if it starts with `{` and ends with `}`; otherwise plain text (added to context only for `UserPromptSubmit`, `UserPromptExpansion`, `SessionStart`, `PostModelSwitch`). Stderr goes to the debug log only. |
| **`2`** | **blocking error.** On events that can block, exit 2 blocks *whether or not you print JSON* — "even a JSON `permissionDecision` of `"allow"` can't override it." The blocking message is the JSON reason if present, otherwise stderr. |
| anything else | **non-blocking error — the action proceeds.** Explicit warning: "Without valid JSON on stdout, Claude Code treats exit code 1 as a non-blocking error and proceeds with the action, even though 1 is the conventional Unix failure code. If your hook is meant to enforce a policy, use `exit 2`." |

Exit 2 per event: `PreToolUse` blocks the tool call; `UserPromptSubmit` blocks and erases the prompt; `PreCompact` blocks compaction; `Stop`/`SubagentStop` prevent stopping; `ConfigChange` blocks the change (except `policy_settings`); `PostToolUse`/`PostToolUseFailure` only show stderr to Claude (the tool already ran); `PermissionRequest` **ignores exit 2** — you must use the `decision` object.

**Fail-open failure modes to know about:**

* A hook whose script path is wrong exits ~127 and is treated as a **non-blocking error**; the action proceeds. "When you set up a policy hook, watch for this notice on its first run: a mistyped path in `settings.json` leaves the gate silently disabled."
* A timed-out `command`/`http`/`mcp_tool` PreToolUse hook **does not block**: "The call continues through the normal permission flow, so don't count on a stalled hook to act as a gate." (Agent SDK callback hooks do block on timeout.)
* HTTP hooks cannot signal blocking through status codes — they must return 2xx with a JSON decision body. Non-2xx, connection failure, and non-JSON 2xx bodies are all non-blocking errors.

### PreToolUse decision control (JSON)

Source: <https://code.claude.com/docs/en/hooks#pretooluse-decision-control>

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Reads of credential files are not allowed"
  }
}
```

* `permissionDecision`: `"allow" | "deny" | "ask" | "defer"`.
* `permissionDecisionReason`: shown to **Claude** for `"deny"`; shown to the user only for `"allow"`/`"ask"`.
* `updatedInput` replaces the whole tool input object before execution.
* `additionalContext` injects a string alongside the tool result.
* Multiple PreToolUse hooks: precedence is **`deny` > `defer` > `ask` > `allow`**.
* A hook `"ask"` forces a prompt even in auto mode (the classifier can still deny, but can't silently approve).
* Deprecated top-level `decision`/`reason` for this event; `"approve"`/`"block"` map to `"allow"`/`"deny"`.

Universal JSON fields (any event): `continue` (false = stop Claude entirely, takes precedence over event decisions), `stopReason`, `systemMessage`, `terminalSequence`. Output strings are capped at 10,000 characters.

### Hooks and permission modes

Source: <https://code.claude.com/docs/en/hooks-guide#hooks-and-permission-modes>

> "`PreToolUse` hooks fire before any permission-mode check, in every permission mode, including `dontAsk`. A hook that returns `permissionDecision: "deny"` blocks the tool even in `bypassPermissions` mode or with `--dangerously-skip-permissions`. This lets you enforce policy that users can't bypass by changing their permission mode.
>
> The reverse is not true: a hook returning `"allow"` doesn't bypass deny rules from settings … Hooks can tighten restrictions but not loosen them past what permission rules allow."

### Example: block secret-file access (adapted from the official example)

The official "Block edits to protected files" script (<https://code.claude.com/docs/en/hooks-guide#block-edits-to-protected-files>), verbatim:

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

Registered with:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          { "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/protect-files.sh" }
        ]
      }
    ]
  }
}
```

To also cover **reads**, widen the matcher to `Read|Edit|Write|NotebookEdit|Grep|Glob` and read the right input field per tool (`file_path` for Read/Edit/Write, `path`+`pattern` for Grep/Glob, `notebook_path` for NotebookEdit). **[UNVERIFIED — the docs do not publish a read-blocking hook example; the input field names come from the parameter-matching section of the permissions page, <https://code.claude.com/docs/en/permissions#match-by-input-parameter>.]**

### Example: block outbound network commands from Bash

Pattern the docs recommend (deny `curl`/`wget` with rules, and use a PreToolUse hook to validate URLs — <https://code.claude.com/docs/en/permissions#read-only-commands>). A minimal implementation, **[UNVERIFIED — my own composition; the shape of the hook contract is documented, the script is not]**:

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

Note the honest caveat: this is a string matcher on a shell command and is defeatable (base64, variable indirection, a script file). Treat it as a speed bump; the sandbox's network layer is the real control. The docs make the same point about `if` filters: "Because the `if` filter is best-effort, use the permission system rather than a hook to enforce a hard allow or deny." (<https://code.claude.com/docs/en/hooks#common-fields>)

### Hook security notes from the docs

`hooks-guide` limitations (<https://code.claude.com/docs/en/hooks-guide#limitations>) and the hooks page's own "Security considerations" section note that hooks run with your full user permissions, are subject to workspace trust, and that `PostToolUse` cannot undo anything.
---

## 6. Environment variables, telemetry, and privacy

### What the model actually sees about your machine

Source: <https://code.claude.com/docs/en/context-window> (the "Environment info" and git blocks) and <https://code.claude.com/docs/en/settings-reference#includegitinstructions>

At session start Claude Code injects, before you type anything:

* **Environment info block** (~280 tokens): "Working directory, platform, shell, OS version, and whether this is a git repo."
* **A git block at the very end of the system prompt**: "the current branch, the main branch, `git status` output, and recent commits."
* CLAUDE.md files, auto memory (`MEMORY.md`, first 200 lines / 25 KB), MCP tool names, skill descriptions.

The working-directory path itself leaks your **username** on most systems (`/Users/<name>/…`, `C:\Users\<name>\…`). There is no setting to redact it. **[UNVERIFIED — I found no documented way to suppress the cwd/platform block; only the git block has a switch.]**

Turn off the git snapshot and the built-in commit/PR instructions:

```json
{ "includeGitInstructions": false }
```

or per session `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS=1` (which takes precedence over the setting).
Source: <https://code.claude.com/docs/en/settings-reference#includegitinstructions>, <https://code.claude.com/docs/en/env-vars>

**Claude Code's system prompt is not published.** (<https://code.claude.com/docs/en/settings#change-a-setting>)

### Are your env vars exposed to the model?

Not as a block in the prompt (nothing in the documented context-window breakdown includes the process environment). But they are exposed **transitively**: sandboxed and unsandboxed Bash commands inherit the parent process environment, so `env`, `printenv`, or `echo $TOKEN` puts them in the transcript. Source: <https://code.claude.com/docs/en/sandboxing#scope> — "sandboxed Bash commands inherit the parent process environment by default, including any credentials set there."

Mitigations:

| Control | Covers |
| :-- | :-- |
| `sandbox.credentials.envVars` with `"mode": "deny"` | unsets the named variables for **sandboxed** Bash commands; works even with `filesystem.disabled` |
| `sandbox.credentials.envVars` with `"mode": "mask"` | replaces with a sentinel; proxy injects the real value only to `injectHosts`; requires `network.tlsTerminate`; user/managed/`--settings` only |
| `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` | strips **Anthropic and cloud-provider credentials** from *all* subprocess environments (Bash tool, hooks, MCP stdio servers) regardless of sandboxing. On Linux it also runs Bash subprocesses in an isolated PID namespace so they can't read host process environments via `/proc` (side effect: `ps`, `pgrep`, `kill` can't see host processes). It also turns `autoAllowBashIfSandboxed` off and makes `filesystem.disabled` ignored from every source. |
| `permissions.deny: ["Bash(env)", "Bash(printenv)", "Bash(export)"]` | **[UNVERIFIED as effective]** — plausible given deny-rule semantics, but the docs give no example and shell expansion (`echo $TOKEN`) is not covered by any command-name rule |

Sources: <https://code.claude.com/docs/en/env-vars> (`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`, `CLAUDE_CODE_SCRIPT_CAPS`), <https://code.claude.com/docs/en/sandboxing#protect-credentials>

### The `env` settings key

Source: <https://code.claude.com/docs/en/settings-reference#env>

```json
{
  "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
  }
}
```

* Sets variables for the session **and every subprocess Claude Code starts**.
* A settings `env` value **overwrites the same variable exported in your shell**. To cancel a shell export, set it to `""`.
* Values are plain text in the file and reach every subprocess — **do not put secrets in `env`**; use `apiKeyHelper` / `otelHeadersHelper` instead.
* From **project and local** settings, `env` applies only after workspace trust — **except in `-p` mode, which never shows the trust dialog and applies them at startup.** This is a real exposure: a hostile repo's `env` block runs in `claude -p`.
* Some variables are ignored from project/local settings: `CLAUDE_CODE_PROCESS_WRAPPER`, `CLAUDE_CODE_SYNC_SKILLS`, `CLAUDE_CODE_SYNC_PLUGINS`, `CLAUDE_CODE_PLUGIN_CACHE_DIR`, `CLAUDE_CODE_PLUGIN_SEED_DIR`; and as of 2.1.251 also `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_TMPDIR`, `TMPDIR`/`TMP`/`TEMP` (<https://code.claude.com/docs/en/changelog>, 2.1.251).
* Ignored from every file: `CLAUDE_CODE_REMOTE`, `CLAUDE_CODE_ACCOUNT_UUID`, `CLAUDE_CODE_MESSAGING_SOCKET`, `CLAUDE_CODE_MESSAGING_TOKEN`, `CLAUDE_CODE_PROJECT_DIR_NAME`, `CLAUDE_CODE_RESTRICTED`.
* Also new in 2.1.251: `ANTHROPIC_CUSTOM_HEADERS` from managed or project settings now requires approval when it sets a credential/routing/API-behaviour header.

### Telemetry and non-essential traffic

Source: <https://code.claude.com/docs/en/data-usage#telemetry-services>, <https://code.claude.com/docs/en/env-vars>

| Variable | Effect |
| :-- | :-- |
| `DISABLE_TELEMETRY` | opts out of usage metrics. "Telemetry events do not include user data like code, file paths, or bash commands." Also disables feature-flag fetching (so Remote Control becomes unavailable). |
| `DISABLE_ERROR_REPORTING` | opts out of error reports (stack traces to a third-party service, with known secret/path/email patterns redacted). |
| `DISABLE_FEEDBACK_COMMAND` (alias `DISABLE_BUG_COMMAND`) | disables `/feedback`, `/bug`, `/share`, and Claude-drafted feedback. |
| `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY` | disables the session-quality survey. |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` | disables auto-updates, telemetry, error reporting, `/feedback`, Claude-drafted feedback, release notes, gateway model discovery, availability checks, and background runs of plugin `command` sources. |
| `DO_NOT_TRACK=1` | same as `DISABLE_TELEMETRY`. |
| `DISABLE_GROWTHBOOK` | disables feature-flag fetching only. |

**Gotcha:** for `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `DISABLE_TELEMETRY`, and `DISABLE_ERROR_REPORTING`, "**Setting it to `0` or `false` still disables this traffic**" — any non-empty value counts. Unset the variable to re-enable.

Two things `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` does **not** cover, each with its own switch:

* **WebFetch domain safety check** — before every fetch, the **hostname** (not the URL, path, or content) is sent to `api.anthropic.com` to check an Anthropic blocklist; cached 5 minutes. Runs on every provider. Disable with `"skipWebFetchPreflight": true` in settings. (<https://code.claude.com/docs/en/data-usage#webfetch-domain-safety-check>)
* Official plugin marketplace auto-install — `CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL`.

Defaults by provider (<https://code.claude.com/docs/en/data-usage#default-behaviors-by-api-provider>): on the Claude API metrics and `/feedback` are **on** by default; error reporting is on only for Pro/Max sign-ins on v2.1.198+ connecting directly to the Claude API without a ZDR/HIPAA agreement. On Bedrock, Google Agent Platform, Foundry, and Claude Platform on AWS, metrics/error reports/feedback default to **off**.

### Data training and retention

Source: <https://code.claude.com/docs/en/data-usage#data-policies>

* **Consumer (Free/Pro/Max)**: Anthropic *will* train on your data (including Claude Code usage) when the setting is on. Opt out at <https://claude.ai/settings/data-privacy-controls> (the Security page also links <https://claude.ai/settings/privacy>). Retention: **5 years** if you allow training, **30 days** if not.
* **Commercial (Team/Enterprise/API/3rd-party/Gov)**: no training on code or prompts unless the org opts into the Development Partner Program. Standard retention 30 days. **Zero Data Retention** is available to qualified Enterprise accounts, per-org, not part of the standard Enterprise plan (<https://code.claude.com/docs/en/zero-data-retention>).
* `/feedback`, `/bug`, `/share` transcripts are retained **5 years**.
* Session-quality-survey transcript shares are retained up to **6 months** and are never used for training.
* I found **no `/privacy-settings` slash command** in the CLI docs. The privacy controls live on claude.ai; Claude Code's local levers are `cleanupPeriodDays`, `desktopSessionCleanupPeriodDays`, and the env vars above. **[The `/privacy-settings` command named in the research brief is UNVERIFIED — not present in <https://code.claude.com/docs/en/commands> or the data-usage page as of 2026-08-30.]**

### Local plaintext exposure

Source: <https://code.claude.com/docs/en/claude-directory#plaintext-storage>

> "Transcripts and history are not encrypted at rest. OS file permissions are the only protection. If a tool reads a `.env` file or a command prints a credential, that value is written to `projects/<project>/<session>.jsonl`."

Levers:

* `cleanupPeriodDays` (default 30, min 1; `0` fails validation — use `3650` for long retention)
* `desktopSessionCleanupPeriodDays` (v2.1.248+; Desktop/Cowork transcripts otherwise have **no age limit**)
* `CLAUDE_CODE_SKIP_PROMPT_HISTORY` — skip writing transcripts and prompt history in any mode
* `--no-session-persistence` with `-p`, or `persistSession: false` in the TypeScript Agent SDK
* `claude project purge <path>` to delete one project's state
* `~/.claude/history.jsonl` holds **every prompt you've typed with timestamp and project path** and is **never** swept by the retention sweep.

---

## 7. MCP server controls

Source: <https://code.claude.com/docs/en/settings-reference#mcp>, <https://code.claude.com/docs/en/mcp>, <https://code.claude.com/docs/en/managed-mcp>

| Key | Scope | Effect |
| :-- | :-- | :-- |
| `enableAllProjectMcpServers` | any file | approves every server in project `.mcp.json` with no prompt. Written to `.claude/settings.local.json` when you choose "approve all". **In a hardened repo this should be absent or `false`.** In an untrusted folder it is honoured only from user/managed/`--settings`. |
| `enabledMcpjsonServers` | any file | array of `.mcp.json` server names to auto-approve |
| `disabledMcpjsonServers` | any file | array of `.mcp.json` server names to **reject outright** — takes precedence over both keys above, and works in every session type including `-p`/SDK |
| `allowedMcpServers` | any file (managed to enforce) | allowlist by `{"serverName"}`, `{"serverCommand": [...]}` (matched exactly), or `{"serverUrl": "...*"}`. Blocks non-matching servers **wherever defined**, including plugin servers, `--mcp-config`, and `managed-mcp.json`. Empty array blocks every server. Built-in servers (Claude in Chrome, the IDE server) and in-process `type: "sdk"` servers are exempt. |
| `deniedMcpServers` | any file | denylist; **takes precedence over `allowedMcpServers`**; merges from every file even under `allowManagedMcpServersOnly` |
| `allowManagedMcpServersOnly` | managed | only the managed allowlist counts |
| `allowAllClaudeAiMcps` | managed | let claude.ai connectors load alongside `managed-mcp.json` |
| `disableClaudeAiConnectors: true` | any file (a `true` anywhere wins) | Claude Code neither fetches nor connects claude.ai MCP connectors. v2.1.182+ |

Restricting MCP **tools** (as opposed to servers):

* `"deny": ["mcp__*"]` — denies every MCP tool from every server and removes them from context
* `"deny": ["mcp__servername"]` or `"deny": ["mcp__servername__toolname"]`
* `"allow": ["mcp__github__get_*"]` — allow-globs are permitted only after a literal `mcp__<server>__` prefix
* Parameter-scoped MCP deny rules must go through `--disallowedTools`; `mcp__` rules with parentheses in a settings file are skipped
* `--strict-mcp-config` — use only servers from `--mcp-config`, ignoring all other MCP configuration
* MCP servers marked `_meta["anthropic/requiresUserInteraction"]` always prompt, even in `auto` and `bypassPermissions`; in `dontAsk` they are denied
* Cowork sessions route shell through `mcp__workspace__bash`; a whole-tool `Bash` **deny** rule is applied to it, but `Bash` **allow** rules are never carried over

Note: `.mcp.json` servers are **connected without asking in `claude -p` / SDK sessions**, approved or not (<https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder>). Use `disabledMcpjsonServers`, `--strict-mcp-config`, or `--bare`.

---

## 8. Other exposure surfaces

### CLAUDE.md and `@file` imports

Source: <https://code.claude.com/docs/en/memory>

Auto-loaded, in load order:

| Scope | Location |
| :-- | :-- |
| Managed policy | macOS `/Library/Application Support/ClaudeCode/CLAUDE.md`; Linux/WSL `/etc/claude-code/CLAUDE.md`; Windows `C:\Program Files\ClaudeCode\CLAUDE.md` |
| User | `~/.claude/CLAUDE.md` |
| Project | `./CLAUDE.md` or `./.claude/CLAUDE.md` |
| Local | `./CLAUDE.local.md` (gitignore it yourself) |

Plus `CLAUDE.md`/`CLAUDE.local.md` in **every directory above cwd** (loaded at launch) and in subdirectories (loaded on demand when Claude reads files there), plus `.claude/rules/`.

`@path/to/import` syntax expands files into context at launch, relative to the importing file, up to 4 hops deep. Imports inside backticks or fenced code blocks are skipped.

**External imports in a project memory file** — one whose path resolves outside the working directory — trigger a one-time approval dialog listing the files. "Claude Code shows the dialog to protect you from files other people commit to a shared project." Imports in **user-scope** memory files load without a dialog. In Cowork desktop sessions, user-scope imports resolving outside the working directory are skipped entirely.

Exclusions: `claudeMdExcludes: ["**/vendor/**/CLAUDE.md"]` (glob or absolute path; does **not** apply to managed-policy CLAUDE.md). Managed orgs can inject memory with the `claudeMd` string key.

Note: CLAUDE.md is delivered as a **user message after the system prompt**, "Claude reads it and tries to follow it, but there's no guarantee of strict compliance." It is **not** an enforcement mechanism — but the auto-mode classifier does read it (<https://code.claude.com/docs/en/auto-mode-config#where-the-classifier-reads-configuration>).

### `.claude/` directory contents

Source: <https://code.claude.com/docs/en/claude-directory>

A repo's `.claude/` can carry: `settings.json`, `settings.local.json`, `CLAUDE.md`, `rules/`, `skills/`, `agents/` (subagents, with frontmatter hooks and inline `mcpServers`), `commands/`, `hooks/`, `workflows/`, `scheduled_tasks.json`, `output-styles/`, `plans/`, plus a sibling `.mcp.json`. All of these are code or configuration a repository can ship to you. `~/.claude/` additionally holds transcripts, `history.jsonl`, `.credentials.json`, and `~/.claude.json` (sign-in session, MCP configs, per-project trust decisions).

`--safe-mode` starts with all of that disabled for troubleshooting: "CLAUDE.md, skills, plugins, hooks, MCP servers, custom commands and agents, output styles, workflows, custom themes, custom keybindings, status line and file-suggestion commands, LSP servers, and auto memory do not load. Authentication, model selection, built-in tools, and permissions work normally." Managed policy hooks/status line/file suggestion still apply. (<https://code.claude.com/docs/en/cli-reference>)

`disableSkillShellExecution: true` blocks inline `` !`...` `` and ```` ```! ```` shell execution in skills and custom commands from user/project/plugin/additional-directory sources (bundled and managed skills unaffected). A `true` in managed settings can't be overridden. (<https://code.claude.com/docs/en/settings-reference#disableskillshellexecution>)

### CLI flags that matter

Source: <https://code.claude.com/docs/en/cli-reference>

| Flag | Note |
| :-- | :-- |
| `--dangerously-skip-permissions` | equivalent to `--permission-mode bypassPermissions`. Blocked when running as root/sudo on Linux/macOS unless inside a recognised sandbox. Blocked entirely by `permissions.disableBypassPermissionsMode`. |
| `--allowedTools` / `--allowed-tools` | adds allow rules for one session. **Ignored entirely when `allowManagedPermissionRulesOnly` is set.** A deny rule from any settings file still blocks. |
| `--disallowedTools` / `--disallowed-tools` | adds deny rules; a bare tool name removes the tool from context; `"mcp__*"` removes every MCP tool. This is the only way to write a parameter-scoped MCP deny rule. |
| `--tools "Bash,Edit,Read"` | restricts which **built-in** tools exist; `""` disables all. Does not affect MCP tools. |
| `--add-dir` | grants file access **and** loads skills/commands/subagents from that directory |
| `--setting-sources user,project,local` | choose which settings files load |
| `--settings <file-or-json>` | applies above user/project/local, below managed |
| `--restricted` | see section 3 |
| `--bare` | no hooks/skills/commands/subagents/plugins/MCP/auto-memory/CLAUDE.md |
| `--safe-mode` | as above |
| `--strict-mcp-config` | only `--mcp-config` servers |
| `--permission-prompt-tool` | MCP tool to answer prompts in `-p` mode |

### Git commit attribution

Source: <https://code.claude.com/docs/en/settings-reference#attribution>

Default: a `Co-Authored-By: <model name> <noreply@anthropic.com>` trailer on commits, `🤖 Generated with [Claude Code](https://claude.com/claude-code)` in PR bodies, and a `Claude-Session` trailer / PR link for cloud and Remote Control sessions.

Hide all of it:

```json
{
  "attribution": {
    "commit": "",
    "pr": "",
    "sessionUrl": false
  }
}
```

(`includeCoAuthoredBy: false` is deprecated since v2.0.62 and is ignored once `attribution.commit` or `attribution.pr` is set.)
---

## 9. Recommended hardened baselines

These are compositions, not copy-paste from the docs. Every individual key is documented (linked in the sections above); the *combination* is my recommendation. Test with `/status`, `/permissions`, `/sandbox` (Config tab), and `claude doctor` before relying on any of it.

Anthropic's own starter files, for comparison, are at <https://github.com/anthropics/claude-code/tree/main/examples/settings> (`settings-lax.json`, `settings-strict.json`, `settings-bash-sandbox.json`) — the README warns they are "community-maintained snippets which may be unsupported or incorrect."

### A. Repo baseline — `.claude/settings.json` (committed)

Design constraints this file respects:

* `deny` and `ask` rules apply **without** workspace trust; `allow` and `additionalDirectories` do not — so this file contains no `allow` rules and no `additionalDirectories`.
* `defaultMode: "auto"` does **not** work from project settings; `"default"` and `"plan"` do.
* `sandbox.filesystem.disabled`, `network.strictAllowlist`, `allowAppleEvents`, credential `mask`, `tlsTerminate`, `awsPairs`, `sigv4` are **ignored** from project settings. `sandbox.enabled`, `filesystem.denyRead`/`denyWrite`, `credentials.*` with `"mode": "deny"`, `excludedCommands`, and `network.allowedDomains`/`deniedDomains` are honoured from any file.
* Cloud sessions read this file and nothing else local.

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

Notes and trade-offs:

* `"WebFetch(domain:*)"` in **deny** both refuses every fetch *and* sets the sandbox's denied-domain list to everything. If you want Claude to be able to read docs, drop it and instead allow specific domains — but remember a bare `WebFetch` allow rule does **not** widen the sandbox host list.
* `"WebSearch"` deny removes the tool from context.
* `Bash(env)` / `Bash(printenv:*)` are **[UNVERIFIED as effective]** — they follow documented deny-rule syntax but the docs give no example, and they cannot stop `echo $TOKEN`.
* `autoAllowBashIfSandboxed: false` costs you prompts. If you want the low-friction version, set it to `true` and rely on the sandbox boundary — that is exactly what the docs call auto-allow mode.
* On **native Windows the whole `sandbox` block is inert.** Run inside WSL2 or a container.
* This file cannot stop a *different* repo checkout from being read: `Read(~/…)` rules are anchored at home so they work, but a sibling project directory is not covered. Use `sandbox.filesystem.denyRead` for that, or `--restricted`.

### B. User baseline — `~/.claude/settings.json`

Remember the anchoring rule: in user settings a bare `/path` resolves to `~/.claude/path`. Use `//` or `~/`.

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

Deliberate choices:

* `network.strictAllowlist` and `credentials.*` `mask` only work from **user/managed/`--settings`**, so they belong here, not in a repo file.
* `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` has side effects: it turns `autoAllowBashIfSandboxed` off, makes `filesystem.disabled` ignored from every source (good), and on Linux hides host processes from `ps`/`pgrep`/`kill`.
* `failIfUnavailable` is left `false` because on native Windows the sandbox never starts and `true` would refuse to launch. Set it to `true` on macOS/Linux/WSL2 fleets.
* `skipWebFetchPreflight` is left `false` deliberately: turning it off means every WebFetch skips Anthropic's malicious-host blocklist. Only set `true` in egress-restricted environments.
* If you also want *no* Anthropic-bound non-essential traffic at all, add `"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"` — but note it also disables auto-updates and feature-flag fetching, which forces the built-in starting permission mode back to `default` (arguably a feature here).

### C. Managed / org baseline — `managed-settings.json`

The only tier that a developer or a repo cannot override.

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

Caution: `allowManagedPermissionRulesOnly: true` means user and project `deny` rules are **also** ignored — the managed list becomes the whole policy. Make it complete before you set it. Same for `allowManagedHooksOnly` and `allowManagedReadPathsOnly`.

---

## Known gaps / caveats

Things a path deny rule (or the permission system generally) does **not** prevent.

1. **Arbitrary subprocesses read denied files freely.** `Read`/`Edit` deny rules only cover the built-in file tools and the file commands Claude Code recognises in Bash (`cat`, `head`, `tail`, `sed`). `python -c "print(open('.env').read())"`, `node -e`, a Makefile target, a test that loads dotenv — none are covered. Only the sandbox's `filesystem.denyRead` is. <https://code.claude.com/docs/en/permissions#read-and-edit>
2. **No sandbox on native Windows.** Seatbelt/bubblewrap only; WSL1 unsupported. On Windows, permission rules and hooks are your entire boundary. <https://code.claude.com/docs/en/sandboxing>
3. **The sandbox fails open by default.** Missing bubblewrap/socat or an unsupported platform = warning + unsandboxed execution, unless `failIfUnavailable: true`. <https://code.claude.com/docs/en/sandboxing#get-started>
4. **Sandbox default read policy is "everything."** `~/.aws/credentials` and `~/.ssh/` are readable by sandboxed commands unless you list them. "There is no built-in credential deny list." <https://code.claude.com/docs/en/sandboxing#protect-credentials>
5. **`excludedCommands` has no managed lock.** Any developer can append entries that run commands entirely outside the sandbox. <https://code.claude.com/docs/en/sandboxing#keep-developers-from-widening-the-policy>
6. **`dangerouslyDisableSandbox` retry is on by default** (`allowUnsandboxedCommands: true`). In auto mode the classifier, not you, decides the retry.
7. **Network allowlisting is hostname-based with no TLS inspection.** Domain fronting can reach hosts outside the allowlist. Allowing a broad host like `github.com` is itself an exfiltration channel (gists, PR bodies, issue comments). <https://code.claude.com/docs/en/sandboxing#security-limitations>
8. **`WebFetch(domain:...)` does not restrict Bash network access,** and blocking WebFetch does not stop `curl`. They are separate channels. <https://code.claude.com/docs/en/permissions#read-only-commands>
9. **Bash argument patterns are structurally unreliable** — flags before the URL, protocol changes, redirects, variable indirection, extra whitespace. Deny the binary, don't try to constrain its arguments.
10. **`Read` deny does not cover `NotebookEdit`** — add an `Edit` deny for the same path. <https://code.claude.com/docs/en/permissions#read-and-edit>
11. **Rules written against the wrong tool are silently inert** (`Write(...)`, `Glob(...)`, `MultiEdit(...)`, `NotebookEdit(...)` path rules). They warn at startup but are never consulted.
12. **`mcp__server(...)` rules with parentheses in a settings file are skipped**, so a "deny this one MCP tool parameter" rule you thought you wrote may not exist. Check `claude doctor`.
13. **`defaultMode: "auto"` is silently ignored from project/local settings**, and when it is present there Claude Code also **ignores** a `defaultMode` from your user settings and uses the built-in default. <https://code.claude.com/docs/en/permission-modes#which-mode-a-session-starts-in>
14. **The VS Code extension ignores project settings for the starting permission mode** and, when feature flags haven't loaded, ignores every settings file.
15. **`claude -p` and the Agent SDK never show the trust dialog.** A repo's hooks, `env` block, `apiKeyHelper`, skill `allowed-tools`, and `.mcp.json` servers all run. `permissions.allow` and `additionalDirectories` do not. Use `--restricted`, `--bare`, `--setting-sources user`, `--settings '{"disableAllHooks": true}'`. <https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder>
16. **Trusting a parent folder is enough for a repo's hooks and `env` block** to run in a nested project.
17. **Hooks fail open.** Bad path -> exit 127 -> non-blocking. Exit 1 -> non-blocking. Timeout on `command`/`http`/`mcp_tool` PreToolUse -> **not blocked**. Only exit 2 (or a valid `permissionDecision: "deny"`) blocks. <https://code.claude.com/docs/en/hooks#other-exit-codes>
18. **Hook `if` filters are best-effort** and the docs say so; when Claude Code can't determine which commands the Bash input runs, it runs the hook regardless — but the converse (a crafted command that dodges the filter) is the risk.
19. **Symlink handling has had real bypasses.** v2.1.251 (2026-08-28) fixed: "file tools (Read, Write, Edit) following a symlink swapped inside the working directory after the permission check, which could read or write outside the approved location", and "Grep and Glob not applying `Read(...)` deny rules to files reached through a symlinked search path." **Pin `requiredMinimumVersion` to 2.1.251 or later.** <https://code.claude.com/docs/en/changelog>
20. **Read-only Bash commands never prompt in any mode** and the list is not configurable — `ls`, `cat`, `grep`, `find`, `git` read-only forms. `cat ~/.aws/credentials` is stopped by the `Read` deny rule, not by the Bash flow; if the deny rule is absent or mis-anchored, it just runs.
21. **Auto mode is a model, not a boundary.** Boundaries you state in conversation "can be lost if context compaction removes the message that stated it." Broad allow rules are dropped on entering auto mode (`Bash(*)`, `Bash(python*)`, package-manager run commands, `Agent` and `Monitor` allow rules), but a narrow rule like `Bash(npm test)` skips the classifier entirely unless you set `autoMode.classifyAllShell: true`. <https://code.claude.com/docs/en/permission-modes#eliminate-prompts-with-auto-mode>
22. **On Pro/Max/Team the built-in starting mode is now `auto`, not manual** (v2.1.228+/2.1.233+). A machine with no `defaultMode` set is *not* in manual mode.
23. **Transcripts are plaintext and unencrypted.** Anything a tool ever read — including a secret printed by an approved command — lands in `~/.claude/projects/<project>/<session>.jsonl` for `cleanupPeriodDays`. `~/.claude/history.jsonl` (every prompt, with project path) is **never** swept. <https://code.claude.com/docs/en/claude-directory#plaintext-storage>
24. **The model always sees cwd, platform, shell, OS version, and (unless disabled) git branch/status/recent commits.** The cwd string usually contains your username. No documented redaction. **[UNVERIFIED that any setting suppresses the environment-info block.]**
25. **`.claude/settings.local.json` is only auto-gitignored when Claude Code creates it.** Hand-created files must be gitignored manually — and Claude Code writes the ignore entry to your *global* excludes file, not the repo's `.gitignore`, so a fresh clone on another machine has no protection.
26. **`env` values in settings are plaintext and reach every subprocess.** Never put credentials there; use `apiKeyHelper`/`otelHeadersHelper`.
27. **Claude Code on the web ignores `bypassPermissions` and `dontAsk` from settings files**, so a repo file can neither start a cloud session in bypass mode (good) nor lock it into `dontAsk` (bad, if that was your plan).
28. **Deny rules can't block `EndConversation`** while any other tool remains.
29. **`allowManagedPermissionRulesOnly` discards your own deny rules too**, not just allow rules. It replaces the whole policy with the managed one.
30. **MCP servers are a parallel tool surface** that path deny rules don't reach; a filesystem MCP server bypasses `Read(...)` deny entirely. Deny `mcp__*` or allowlist by `serverCommand`/`serverUrl`.

---

## Detection checklist

What a scanner should look for to judge how hardened a Claude Code setup is. Grouped by where it looks.

### In the repo

| Check | Signal |
| :-- | :-- |
| `.claude/settings.json` exists and is committed | baseline present |
| `permissions.deny` contains `.env` patterns (`Read(./.env)`, `Read(**/.env*)`) | ✅ |
| `permissions.deny` covers key material (`**/*.pem`, `**/id_rsa*`, `**/secrets/**`, `**/credentials*`, `**/*.tfstate`) | ✅ |
| `permissions.deny` covers home-anchored credentials (`~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, `~/.kube/**`, `~/.config/gcloud/**`) | ✅ |
| Deny rules use `~/` or `//` anchors where they mean absolute — **flag single-leading-slash rules** like `Read(/Users/...)` or `Read(/home/...)` as mis-anchored | ⚠️ |
| `Edit(...)` deny rules exist alongside `Read(...)` for paths nothing may change (NotebookEdit gap) | ✅ |
| **`Write(...)`, `Glob(...)`, `MultiEdit(...)`, `NotebookEdit(<path>)` path rules present** | ⚠️ inert rules — false sense of security |
| `Bash(curl*)` / `Bash(wget*)` denied, or an egress hook present | ✅ |
| Bash rules that try to constrain arguments (`Bash(curl https://x/ *)`) | ⚠️ fragile |
| `permissions.allow` contains `Bash`, `Bash(*)`, `Bash(python*)`, `Bash(sh *)`, `Bash(npx *)`, `Bash(docker *)`, `Bash(devbox run *)`, `Bash(direnv exec *)` | 🚨 arbitrary code execution |
| `permissions.allow` contains `Read(~/...)`, `Read(//...)`, or anything outside the repo | 🚨 |
| `permissions.additionalDirectories` non-empty | ⚠️ out-of-repo access |
| `permissions.defaultMode` is `bypassPermissions` or `acceptEdits` | 🚨 / ⚠️ |
| `permissions.defaultMode` is `"auto"` in a **project** file | ⚠️ silently ignored, and it suppresses the user-level value |
| `permissions.disableBypassPermissionsMode: "disable"` present | ✅ |
| `sandbox.enabled: true` | ✅ (inert on native Windows) |
| `sandbox.autoAllowBashIfSandboxed` explicit | informational — `true` is the default and means no prompts |
| `sandbox.allowUnsandboxedCommands: false` | ✅ strict mode |
| `sandbox.excludedCommands` non-empty | ⚠️ each entry is a hole |
| `sandbox.filesystem.denyRead` covers `~/.ssh`, `~/.aws`, `~/.claude` | ✅ |
| `sandbox.credentials.files` / `.envVars` deny entries present | ✅ |
| `sandbox.network.allowedDomains` contains `*` or a bare wildcard | 🚨 |
| `sandbox.network.allowAllUnixSockets: true` or `allowUnixSockets` containing `docker.sock` | 🚨 sandbox escape |
| `sandbox.enableWeakerNestedSandbox` / `enableWeakerNetworkIsolation` / `allowAppleEvents` true | ⚠️ / 🚨 |
| `sandbox.filesystem.disabled: true` in a project file | informational — **ignored** from project scope by design |
| `WebFetch(domain:*)` in `allow` | 🚨 also opens the sandbox to every host |
| `enableAllProjectMcpServers: true` | 🚨 auto-approves every `.mcp.json` server |
| `.mcp.json` present, and whether `disabledMcpjsonServers` / `allowedMcpServers` constrain it | ⚠️ |
| `hooks` present: do the referenced scripts **exist and are executable**? | a mistyped path silently disables the gate |
| Hook scripts use `exit 2` (not `exit 1`) to block | 🚨 `exit 1` does not block |
| Hook `timeout` values — a PreToolUse `command` hook that times out does **not** block | ⚠️ |
| `env` block in `.claude/settings.json` — inspect every entry; it runs in `claude -p` without trust | ⚠️ |
| `.gitignore` contains `.claude/settings.local.json` | ✅ (auto-ignore only happens on the machine that created it) |
| `.claude/settings.local.json` is **tracked in git** | 🚨 personal allow rules shipped to everyone; also flips it to trust-gated |
| `.claude/` contains `hooks/`, `agents/`, `commands/`, `skills/`, `workflows/`, `scheduled_tasks.json` | each is executable/config content shipped by the repo — review |
| `CLAUDE.md` / `.claude/rules/` contain `@` imports resolving outside the repo | ⚠️ triggers an approval dialog interactively, but review anyway |
| `attribution.commit` / `.pr` / `.sessionUrl` set | informational (attribution leakage preference) |
| `includeGitInstructions: false` | informational (git status not in prompt) |

### In user config (`~/.claude/`)

| Check | Signal |
| :-- | :-- |
| `settings.json` has `permissions.deny` for `~/.ssh/**`, `~/.aws/**`, `~/.claude/.credentials.json`, `~/.claude.json` | ✅ |
| Deny rules using bare `/path` in user settings | 🚨 anchors at `~/.claude/path`, almost certainly not what was meant |
| `permissions.defaultMode` present; absent means the plan's built-in default, which is **`auto`** on Pro/Max/Team | ⚠️ |
| `permissions.disableBypassPermissionsMode: "disable"` | ✅ |
| `skipDangerousModePermissionPrompt: true` | ⚠️ the bypass-mode warning dialog has been accepted |
| `sandbox.enabled`, `sandbox.network.strictAllowlist`, `sandbox.credentials.*` | ✅ (these only work from user/managed/`--settings`) |
| `env`: `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`, `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` | ✅ privacy posture |
| `cleanupPeriodDays` (default 30) and `desktopSessionCleanupPeriodDays` (default 0 = **no limit** for Desktop/Cowork) | ⚠️ |
| `~/.claude/projects/**` and `~/.claude/history.jsonl` exist and are world/group-readable | 🚨 plaintext secrets at rest |
| `~/.claude.json` `projects["<path>"].hasTrustDialogAccepted` — which folders are trusted | informational |
| Shell aliases / wrapper scripts that inject `--dangerously-skip-permissions` | 🚨 |

### System / managed

| Check | Signal |
| :-- | :-- |
| `managed-settings.json` present at the OS path (macOS `/Library/Application Support/ClaudeCode/`, Linux/WSL `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\`), or `managed-settings.d/*.json` | ✅ policy tier in use |
| `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `sandbox.filesystem.allowManagedReadPathsOnly`, `sandbox.network.allowManagedDomainsOnly` | ✅ locks — but verify the managed lists are complete, since these discard local rules |
| `permissions.disableBypassPermissionsMode` + `disableAutoMode` | ✅ |
| `sandbox.failIfUnavailable: true` | ✅ fail closed |
| `strictKnownMarketplaces` (`[]` = no plugin marketplaces) | ✅ |
| `disableSkillShellExecution: true` | ✅ |
| `requiredMinimumVersion` ≥ `2.1.251` | ✅ picks up the symlink and Grep/Glob deny-rule fixes |
| Platform is native Windows while policy relies on `sandbox` | 🚨 the sandbox block does nothing |

### Runtime verification commands

* `/status` — the `Setting sources` line names every settings file loaded and which managed source applies
* `/permissions` — every rule and the file it came from; the **Auto mode** tab shows classifier rules
* `/sandbox` — Mode, Overrides, Config (the **Denied within allowed** list resolves protected paths for your machine), Dependencies
* `claude doctor` — lists rejected settings entries, skipped `mcp__(...)` rules, `injectHosts` that can never match, and unreliable IPv6 domain spellings
* `claude auto-mode defaults` — prints the classifier's full built-in rule lists as JSON
* `/context` — shows which memory files loaded
* `claude --version` — compare against `requiredMinimumVersion` and the changelog fixes above

---

## Source index

Docs (all under `https://code.claude.com/docs/en/`; the old `docs.anthropic.com/en/docs/claude-code/*` URLs 301 here):

* `settings` — hierarchy, precedence, cloud sessions, managed exceptions
* `settings-reference` — every key, with scope/type/default (`#permission-settings`, `#sandbox-settings`, `#mcp`, `#env`, `#privacy-and-telemetry`, `#git-and-attribution`, `#hooks-and-automation`)
* `settings-example` — a developer file, a team file, a managed file
* `permissions` — rule syntax, path anchoring, Bash internals, WebFetch, MCP, Cd, workspace trust
* `permission-modes` — modes, auto-mode classifier, protected paths, critical paths
* `sandboxing` — OS support, filesystem/network layers, credentials, limitations
* `sandbox-environments` — containers, VMs, sandbox-runtime
* `hooks` — full reference, events, exit codes, decision control
* `hooks-guide` — worked examples, limitations, hooks vs permission modes
* `security` — safeguards, prompt injection, MCP security, cloud execution
* `data-usage` — training/retention policy, telemetry services, WebFetch preflight
* `env-vars` — every environment variable
* `memory` — CLAUDE.md locations, `@` imports, external-import approval
* `claude-directory` — what lives in `.claude/` and `~/.claude/`, plaintext storage, retention
* `context-window` — what loads into context at startup, including the environment-info block
* `mcp`, `managed-mcp` — MCP configuration and org controls
* `managed-settings`, `server-managed-settings`, `admin-setup` — policy delivery
* `cli-reference` — flags including `--restricted`, `--bare`, `--safe-mode`, `--setting-sources`
* `auto-mode-config` — classifier rules and `permissions.ask` boundary recipes
* `zero-data-retention`, `legal-and-compliance`
* `changelog` — <https://code.claude.com/docs/en/changelog> (mirrors <https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md>)

GitHub:

* <https://github.com/anthropics/claude-code/tree/main/examples/settings> — `settings-lax.json`, `settings-strict.json`, `settings-bash-sandbox.json`, README
* <https://github.com/anthropics/claude-code/blob/main/examples/hooks/bash_command_validator_example.py> — referenced by the hooks docs as the reference Bash command validator (not fetched during this research)
* <https://github.com/anthropics/claude-code/tree/main/examples/mdm> — MDM deployment templates (referenced by the settings-examples README; not fetched)
* <https://github.com/anthropic-experimental/sandbox-runtime> — standalone sandbox primitives

JSON schema for editor validation: <https://json.schemastore.org/claude-code-settings.json> (the docs note it "can lag behind the newest CLI releases").
