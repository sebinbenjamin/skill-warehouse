# Aider · Cline · Roo Code · Amp · Kiro: hardening reference
Verified against: vendor docs as of 2026-08-30.

Common to all five: **none has a repo-committable permission policy.** Aider has no permission model at all; Cline, Roo, Amp, and Kiro keep permission state in user-level or extension-global storage. A repo scan can confirm ignore files and instruction files only.

*The standard set* below means, one glob per line in gitignore syntax: `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `.netrc`, `.npmrc`, `secrets/`.

## Aider
Verified against: <https://aider.chat/docs/config/options.html>, 2026-08-30.

### Config surfaces
| File | Scope | Committed? | Precedence / trust notes |
|---|---|---|---|
| `.aiderignore` (git root) | repo | **yes** | Path overridable by `--aiderignore` / `AIDER_AIDERIGNORE`. |
| `.aider.conf.yml` (project root) | repo | **yes** | Mirrors CLI flags as YAML keys. **[UNVERIFIED: precedence rules (the config page was not fetched).]** |
| CLI flags / `AIDER_*` env vars | invocation | - | Every flag has an `AIDER_*` env equivalent; env silently overrides committed YAML. |

### What each control actually stops
| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `.aiderignore` | T6 ignore file | Files being added to the chat / repo map | Shell and command execution: not an access-control boundary |
| `--subtree-only` (default `false`) | T4 harness deny rule (weak) | "Only consider files in the current subtree of the git repository" | Shell access to those files |
| `--no-auto-commits` (auto-commits default **on**); `--analytics-disable` | - (blast radius / data routing) | Automatic committing of LLM changes; analytics, permanently | The edits themselves; provider-side retention |
| *(nothing else)* | - | Absent: T1, T2, T3, T5, and any real T4. The reference "contains no sandboxing or permission-restriction options beyond read-only file specification"; `--read FILE` only marks a file read-only | **Treat Aider as an unsandboxed harness** |

### Rule semantics you must get right
1. `--yes-always` / `AIDER_YES_ALWAYS` / `yes-always: true`: "Always say yes to every confirmation". Total bypass; the YOLO flag.
2. Aider adds `.aider*` to `.gitignore` by default unless `--no-gitignore` / `AIDER_GITIGNORE`.
3. `.aiderignore` scopes chat/repo-map inclusion only; never cite it as protection against shell reads.

### Detection checklist
| Check | Severity | Where to look |
|---|---|---|
| repo-visible: `--yes-always` / `yes-always: true` in scripts, Makefiles, CI, or docs, with no container | Critical | `Makefile`, `.github/workflows/**`, `package.json`, `README*` |
| repo-visible: no permission mechanism exists at all; `.aiderignore` is the only protection | High | repo root |
| repo-visible: `.aiderignore` missing or not covering the standard set | High | repo root |
| repo-visible: `.aider.conf.yml` missing `auto-commits: false` / `analytics-disable: true`; `.gitignore` missing `.aider*`; `subtree-only` unset in a monorepo subtree | Medium | repo root |
| out-of-band: `AIDER_YES_ALWAYS` or any loosening `AIDER_*` var exported in a shell profile or CI | Critical | `~/.bashrc`, `~/.zshrc`, CI variables |

### Hardened baseline
`.aider.conf.yml` (repo-committable):
```yaml
auto-commits: false
analytics-disable: true
yes-always: false
```
`.aiderignore` (repo-committable): the standard set. Nothing else is settable from repo scope: there is no permission, sandbox, or user-level policy file to write.

### Verify at runtime
`env | grep AIDER_`; `cat .aider.conf.yml .aiderignore`; confirm no wrapper script or shell alias injects `--yes-always`.

## Cline
Verified against: <https://docs.cline.bot/customization/clineignore>, <https://docs.cline.bot/features/auto-approve>, 2026-08-30.

### Config surfaces
| File | Scope | Committed? | Precedence / trust notes |
|---|---|---|---|
| `.clineignore` (repo root) | repo | **yes** | Gitignore syntax; per-workspace-root in monorepos. Cline's own docs mark it **"(deprecate soon)"**. |
| `.clinerules` / `.clinerules/` | repo | yes | Model instructions, not enforcement. |
| Auto-approve toggles (Cline Settings → Features) | user | **no** | Storage undocumented. **[UNVERIFIED: whether auto-approve state is repo-committable. It appears to be VS Code extension global state, i.e. not repo-committable.]** |

### What each control actually stops
| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `.clineignore` | T6 ignore file | Guards file reads/edits (`read_files`, editor, `apply_patch`) | Verbatim: "not a security or access-control boundary — ignored files can still be read via explicit `@` mentions or shell commands." Also does not filter `search_files` / `list_files` results |
| Auto-approve toggles (8 of them) | T4 harness deny rule | Whichever categories are left off | Anything once a category is on |
| `.clinerules` | T7 instruction file | Nothing; steering only | Any tool call |
| *(nothing else)* | - | Absent: T1, T2, T3, T5 | - |

### Rule semantics you must get right
1. The eight toggles: Read project files, Read all files, Edit project files, Edit all files, Execute safe commands, Execute all commands, Use the browser, Use MCP servers.
2. **"Read all files" and "Edit all files" explicitly extend beyond the workspace**; these two are the out-of-repo escape and should always be off.
3. **Command safety is model-judged, not list-based**: "The model marks each command with a `requires_approval` flag based on the command and arguments." A prompt-injected model can mark a malicious command safe.
4. **YOLO Mode** auto-approves everything: files, terminal, browser, MCP, mode transitions.

### Detection checklist
| Check | Severity | Where to look |
|---|---|---|
| repo-visible: repo docs telling users to enable YOLO Mode | Critical | `README*`, `.clinerules*`, `CONTRIBUTING*` |
| repo-visible: `.clineignore` is the only protection present (ignore-file-only, vendor-disclaimed), or is missing / not covering the standard set; `.clinerules` claiming security guarantees | High | repo root, `.clinerules` |
| out-of-band: YOLO Mode enabled, or "Execute all commands" on, with no container | Critical | Cline Settings → Features |
| out-of-band: "Read all files" / "Edit all files" on (out-of-workspace escape); "Use MCP servers" auto-approved | High | same |

### Hardened baseline
`.clineignore` (the only repo-committable control): the standard set. Everything else is **ignored from repo scope**: the eight auto-approve toggles and YOLO Mode live in extension settings and must be set per developer; there is no user-level file to hand over either.

### Verify at runtime
Cline Settings → Features: confirm YOLO Mode off, "Execute all commands" off, "Read all files" / "Edit all files" off. Empirically, `@`-mention an ignored file and run `cat .env` in the terminal; both are expected to succeed, which is the point.

## Roo Code
Verified against: <https://roocodeinc.github.io/Roo-Code/features/rooignore>, 2026-08-30.

### Config surfaces
| File | Scope | Committed? | Precedence / trust notes |
|---|---|---|---|
| `.rooignore` (workspace root) | repo | **yes** | Gitignore syntax. Scope is the VS Code workspace root only. **Roo cannot modify `.rooignore` itself.** |
| `.roo/` rules | repo | yes | Model instructions, not enforcement. |
| Auto-approve settings | user | **no** | Granular, analogous to Cline's. |

### What each control actually stops
| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `.rooignore` on file tools | T6 ignore file | `read_file` "will not read ignored files"; `write_to_file` will not write or create them; `apply_diff` will not patch them; `list_files` / `@directory` filtered or marked 🔒; single-file mentions return `(File is ignored by .rooignore)` | Paths outside the workspace root |
| `.rooignore` on `execute_command` | T6 ignore file (partial) | "checks if a command (from a predefined list like `cat` or `grep`) targets an ignored file. If so, execution is blocked." **The only harness here that gates shell reads via its ignore file** | Verbatim: "Protection for `execute_command` is limited to a predefined list of file-reading commands. Custom scripts or uncommon utilities might not be caught." |
| Auto-approve settings | T4 harness deny rule | Whichever categories are left off | Anything once on |
| *(nothing else)* | - | Absent: T1, T2, T3, T5 | Vendor disclaimer, verbatim: "`.rooignore` is a powerful tool for controlling Roo's file access via its tools, but it does not create a system-level sandbox." |

### Rule semantics you must get right
1. The `execute_command` guard matches a **predefined command list**. `python -c`, `base64`, `xxd`, `head`, `perl -ne`, and any custom script bypass it. Score it as a plus relative to peers, never as a boundary.
2. Enforcement scope is the VS Code workspace root; paths outside it are unprotected.
3. Roo cannot edit `.rooignore`, so a committed file cannot be tampered with by the agent.

### Detection checklist
| Check | Severity | Where to look |
|---|---|---|
| repo-visible: `.rooignore` absent (no control of any kind), the only protection (ignore-file-only), or not covering the standard set; `.roo/` rules asserting protections the tools do not provide | High | workspace root, `.roo/` |
| out-of-band: auto-approve for command execution enabled with no container | Critical | Roo auto-approving-actions settings |
| out-of-band: auto-approve for out-of-workspace read/write enabled | High | same |

### Hardened baseline
`.rooignore` (repo-committable): the standard set. **Ignored from repo scope:** all auto-approve toggles.

### Verify at runtime
Confirm the 🔒 marker appears in `list_files` output for ignored paths and that a single-file `@` mention returns `(File is ignored by .rooignore)`. Then run `cat .env` (blocked) followed by `head .env` or `python -c "print(open('.env').read())"` (expected to succeed; demonstrate the gap).

## Amp
Verified against: <https://ampcode.com/security>, <https://ampcode.com/news/tool-level-permissions>, <https://ampcode.com/news/mcp-permissions>, 2026-08-30.

### Config surfaces
| File | Scope | Committed? | Precedence / trust notes |
|---|---|---|---|
| `amp.permissions` (Amp settings key) | user | **no** | Edited via "Amp: Edit User Permissions" in VS Code. **[UNVERIFIED: exact settings-file path; the CLI equivalent was not confirmed, nor whether a repo-committed file can set it.]** Assume user-level only. |
| `amp.mcpPermissions` | user | no | Rules that block or allow MCP servers. |
| `AGENTS.md` | repo | yes | Amp's instruction file: the only repo-visible surface. |

### What each control actually stops
| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `amp.permissions` rule, `action: "reject"` (or `"delegate"` to a helper on `$PATH`) | T4 harness deny rule | The matched tool/argument combination | Anything not matched by `tool` + `matches` |
| `amp.mcpPermissions` | T4 harness deny rule | MCP servers by rule | Non-MCP tools |
| Automatic secret redaction | T3 credential scrub | "automatically detects and redacts secrets before they can enter threads or be transmitted to external services", replacing them with markers like `[REDACTED:amp]`; covers AWS, Google Cloud, Azure credentials plus dev platforms, LLM APIs, Stripe, Slack | Verbatim: "may miss non-standard formats, encoded secrets, or custom internal systems." Amp still advises "keeping secrets out of files the agent can read" |
| e2b ephemeral compute (Amp "orbs") | T1 OS sandbox | Isolates orb execution | Non-orb local execution |

### Rule semantics you must get right
1. Rule shape: `tool` (e.g. `"Bash"`, `"mcp__*"`, `"*"`), `matches` (optional argument matcher, e.g. `{ "cmd": "*git commit*" }` or `{ "cmd": ["*python *", "*python3 *"] }`), `action` (`"allow"` | `"ask"` | `"reject"` | `"delegate"`), `to` (with `delegate`, "a permission helper (must be on `$PATH`)").
2. Redaction is defence in depth, not a boundary. Remediation for a leaked secret is editing preceding messages or marking threads private.
3. Data tiers: Enterprise has "Minimal Data Retention"; providers may retain safety/abuse data up to 30 days; on Enterprise workspaces training "can *never* be enabled"; other tiers require workspace admin approval for training. Linked personal ChatGPT/Grok subscriptions fall under those providers' controls, which Amp cannot override.

### Detection checklist
| Check | Severity | Where to look |
|---|---|---|
| repo-visible: no Amp control is repo-verifiable; report the harness as unverifiable and check `AGENTS.md` asserts no false guarantees | Info | repo root |
| out-of-band: `amp.permissions` has no `reject`/`ask` rules for credential-reading `Bash` commands, or no catch-all `{"tool": "*", "action": "ask"}` | High | "Amp: Edit User Permissions" |
| out-of-band: non-Enterprise tier with training not declined, or a linked personal ChatGPT/Grok subscription (training-eligible auth tier) | High | Amp workspace settings |
| out-of-band: `amp.mcpPermissions` does not restrict MCP servers; redaction relied on as the primary control; an `amp.dangerouslyAllowAll`-style setting enabled. **[UNVERIFIED that such a key exists: seen only in third-party writeups, not vendor docs.]** | Medium | Amp user settings |

### Hardened baseline
There is **no repo-committable Amp config**; repo scope carries only `AGENTS.md` guidance. Supply this for user settings (`amp.permissions`), noting the unverified path:
```json
{
  "amp.permissions": [
    { "tool": "Bash", "matches": { "cmd": ["*.env*", "*printenv*", "*/.ssh/*", "*/.aws/*"] }, "action": "reject" },
    { "tool": "Bash", "matches": { "cmd": ["*curl *", "*wget *"] }, "action": "ask" },
    { "tool": "mcp__*", "action": "ask" },
    { "tool": "*", "action": "ask" }
  ]
}
```

### Verify at runtime
"Amp: Edit User Permissions" in VS Code shows the live `amp.permissions` array. Test redaction by having the agent read a file holding a well-formed AWS key and confirming `[REDACTED:amp]` in the thread. Confirm workspace tier and training setting in Amp workspace settings.

## Kiro
Verified against: <https://kiro.dev/docs/permissions/>, <https://kiro.dev/docs/kiroignore/>, 2026-08-30.

### Config surfaces
| File | Scope | Committed? | Precedence / trust notes |
|---|---|---|---|
| `~/.kiro/settings/permissions.yaml` | user | no | Deny > ask > allow. |
| `~/.kiro/workspace-roots/<hash>/permissions.yaml` | "workspace" | **no: stored per-user outside the repository** | This is why Kiro permissions are not repo-committable. |
| `.kiroignore` (repo root) | repo | **yes** | Gitignore syntax; cannot re-include a file under an excluded parent directory. |
| `.kiro/settings/`, `.kiro/agents/**`, `.kiro/hooks/**` | repo | yes | Agent can never write `.kiro/settings/`; always prompts before writing `.git/**`, `.kiro/agents/**`, `.kiro/hooks/**`, `.kiroignore`. A human can still commit weak or hostile ones. |
| `kiroAgent.agentAutonomy`, `kiroAgent.agentIgnoreFiles` (IDE settings) | user/workspace | via committed VS Code settings | `agentIgnoreFiles` takes ignore filenames, e.g. `[".gitignore", ".kiroignore"]`, and **can be set to `[]` to disable ignoring entirely**. |

### What each control actually stops
| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| `permissions.yaml` `effect: deny` | T4 harness deny rule | The matched capability. "**deny > ask > allow — a deny rule always wins regardless of scope**" | Anything at all if the file is missing; it lives per-user, outside the repo |
| `sandbox_network` capability | T2 egress allowlist | Network per rule | Non-network exfil |
| `.kiroignore` | T6 ignore file | **IDE**: full enforcement across agent tools ("prevents Kiro from reading specific files") | **CLI V3**: filters content-search and filename-search results only. **Web**: "not available yet". **Mobile**: no support. **[UNVERIFIED: shell coverage of `.kiroignore`. Assume not covered; use a `capability: shell` deny rule.]** |
| Autonomy mode (`kiroAgent.agentAutonomy`) | T4 harness deny rule | **Supervised** prompts before any action; **Autopilot** proceeds with allowed operations without prompting | Capability permissions apply *after* the autonomy mode decides whether to proceed |
| *(nothing else)* | - | Absent: T3 credential scrub; T1 is only the partial `sandbox_network` capability | - |

### Rule semantics you must get right
1. Schema:
   ```yaml
   rules:
     - capability: [capability_name]
       match: [glob_patterns]
       exclude: [glob_patterns]   # optional
       effect: [deny|ask|allow]
   ```
2. Capabilities: `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, `mcp`, `subagent`, `skill`, `power`, `context`, `diagnostics`, `sandbox_network`. Meta: `all`, `builtin`, `filesystem`.
3. Precedence is **deny > ask > allow regardless of scope**, unlike OpenCode's last-match-wins.
4. The vendor examples cover `fs_write`, not reads. For secret *reading* use `capability: fs_read` with the same match list plus `~/.ssh/**`, `~/.aws/**`.
5. `.kiroignore` coverage is uneven by surface (IDE / CLI V3 / Web / Mobile); always state which surface a verdict applies to. `kiroAgent.agentIgnoreFiles: []` disables ignore files entirely.

### Detection checklist
| Check | Severity | Where to look |
|---|---|---|
| repo-visible: committed `kiroAgent.agentAutonomy` = Autopilot with no container, or `kiroAgent.agentIgnoreFiles: []` (disables ignoring entirely) | Critical | `.vscode/settings.json`, `*.code-workspace` |
| repo-visible: `.kiro/hooks/**` or `.kiro/agents/**` committed with unreviewed executable behaviour | Critical | `.kiro/` |
| repo-visible: `.kiroignore` absent, not covering the standard set, or the only protection present | High | repo root |
| repo-visible: `.kiro/settings/` committed weak; repo docs claiming `.kiroignore` protects the CLI | Medium | `.kiro/`, `README*` |
| out-of-band: autonomy mode = Autopilot with no container | Critical | Kiro IDE settings |
| out-of-band: no `fs_read` deny rules for credential paths, or no `shell` deny rules, in `~/.kiro/workspace-roots/<hash>/permissions.yaml`; `web_fetch` not `ask`; `mcp` unrestricted | High | user config |

### Hardened baseline
`.kiroignore` (repo-committable): the standard set. **Ignored from repo scope:** all of `permissions.yaml` (both locations sit under `~/.kiro/`) and the autonomy mode. Write this to `~/.kiro/settings/permissions.yaml` and/or `~/.kiro/workspace-roots/<hash>/permissions.yaml`:
```yaml
rules:
  - capability: fs_read
    match: ["*.env", "*.env.*", "*.pem", "*.key", "id_rsa*", "**/.netrc", "**/.npmrc", "~/.ssh/**", "~/.aws/**", "~/.kube/**", "~/.config/gcloud/**"]
    effect: deny
  - capability: fs_write
    match: ["*.env", "*.pem", "*.key"]
    effect: deny
  - capability: shell
    match: ["rm -rf *", "sudo *", "env", "printenv*", "cat *.env*", "cat ~/.ssh/*", "curl *", "wget *"]
    effect: deny
  - capability: shell
    match: ["*"]
    effect: ask
  - capability: web_fetch
    match: ["*"]
    effect: ask
  - capability: mcp
    match: ["*"]
    effect: ask
```

### Verify at runtime
Read `~/.kiro/settings/permissions.yaml` and the matching `~/.kiro/workspace-roots/<hash>/permissions.yaml` (identify the hash by matching the workspace path). In Kiro IDE settings confirm `kiroAgent.agentAutonomy` = Supervised and `kiroAgent.agentIgnoreFiles` is non-empty. Test `fs_read` of `.env` (expect deny) and shell `cat .env` (expect deny from the shell rule, since `.kiroignore` shell coverage is unverified).

## Sources
- Aider: <https://aider.chat/docs/config/options.html>
- Cline: <https://docs.cline.bot/customization/clineignore>, <https://docs.cline.bot/features/auto-approve>
- Roo Code: <https://roocodeinc.github.io/Roo-Code/features/rooignore>, <https://roocodeinc.github.io/Roo-Code/features/auto-approving-actions/>
- Amp: <https://ampcode.com/security>, <https://ampcode.com/news/tool-level-permissions>, <https://ampcode.com/news/mcp-permissions>
- Kiro: <https://kiro.dev/docs/permissions/>, <https://kiro.dev/docs/kiroignore/>
