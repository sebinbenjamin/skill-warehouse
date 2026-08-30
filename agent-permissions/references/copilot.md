# GitHub Copilot: hardening reference
Verified against: docs.github.com as of 2026-08-30.

Three distinct products with three distinct control planes: **Copilot Chat/completions** (content exclusion, settings-UI only), the **Copilot coding agent** (firewall, settings-UI only), and **Copilot CLI** (files, partly repo-committable).

## Config surfaces

| File / location | Scope | Committed to repo? | Precedence / trust notes |
|---|---|---|---|
| Settings → Copilot → **Content exclusion** | repo / org / enterprise | **no: settings UI only** | Repo admins, org owners, enterprise owners can edit; the "Maintain" role can view only. There is no `.github/copilot` content-exclusion file and no `copilot.exclude` repo key in primary docs. **[UNVERIFIED that no such file exists; no doc for one was found.]** |
| Settings → Copilot → **Internet access** (coding agent firewall) | org / repo | no | Org: `Enabled` / `Disabled` / `Let repositories decide`. Repo-level toggle exists only if the org says "let repositories decide". Two independent switches: **Enable firewall** and **Recommended allowlist**. |
| Actions variables `COPILOT_AGENT_FIREWALL_ALLOW_LIST`, `COPILOT_AGENT_FIREWALL_ALLOW_LIST_ADDITIONS` | repo | yes | The first replaces the default list (comma-separated hosts), the second adds to it. Current firewall page says only that "Previous configurations saved as Actions variables will be maintained"; the UI has superseded them. **[Partially verified: the variables are real but appear legacy as of 2026-08.]** |
| `.github/workflows/copilot-setup-steps.yml` | repo | yes | Coding-agent environment customization: runner, `permissions:` block, services, ≤59 min timeout. Executable configuration. |
| Built-in defaults | - | no | Copilot CLI cascade layer 1. |
| MDM managed settings | machine | no | Layer 2. |
| `~/.copilot/settings.json` (or `$COPILOT_HOME`, or `--config-dir=DIRECTORY`) | user | no | Layer 3. JSONC, user-editable. |
| `.github/copilot/settings.json` | repo | **yes** | Layer 4: the repo-enforceable Copilot CLI surface. |
| `.github/copilot/settings.local.json` | repo dir | no, **should be gitignored** | Layer 5, personal override layer. |
| Environment variables | shell | - | Layer 6. |
| Command-line flags | invocation | - | Layer 7, highest. |
| `~/.copilot/config.json` | user | no | Auto-managed state: do not edit. Holds `trustedFolders` array. |
| `~/.copilot/permissions-config.json` | user | no | Saved approvals per location. A **grant store, not a policy file**; it only ever widens. |
| `~/.copilot/mcp-config.json`, `lsp-config.json`, `copilot-instructions.md` | user | no | MCP servers, LSP, instruction text. |
| `.claude/settings.json`, `.claude/settings.local.json` | repo | yes | **Also consumed by Copilot CLI** for a shared cross-tool subset: `companyAnnouncements`, `disableAllHooks`, `enabledPlugins`, `extraKnownMarketplaces`, `hooks`. A repo-committed Claude hooks block therefore runs under Copilot CLI too. |

## What each control actually stops

| Control | Tier | Stops | Does NOT stop |
|---|---|---|---|
| Content exclusion (settings UI) | T6 ignore file | Matched paths feeding inline suggestions (VS/VS Code/JetBrains/Vim/Neovim/Xcode/Eclipse) and Chat (VS/VS Code/JetBrains/github.com/GitHub Mobile) | Verbatim: **"Content exclusion is currently not supported in Edit and Agent modes of Copilot Chat in Visual Studio Code and other editors."** Also not Xcode Chat, Eclipse Chat, Azure Data Studio. Also: semantic info leaked indirectly by the IDE (type information, hover-over definitions, build configuration), symlinks, and repositories on remote filesystems. Not listed as supported for Copilot CLI or the coding agent. **[UNVERIFIED: absence from the support table is not an explicit "not supported" statement. Treat content exclusion as providing no agent-mode protection until GitHub says otherwise.]** |
| Coding agent firewall | T2 egress allowlist | Outbound hosts outside the allowlist. Verbatim: **"Disabling the firewall will allow Copilot to connect to any host, increasing risks of exfiltration of code or other sensitive information."** | Nothing on self-hosted or Windows runners: the firewall is **incompatible** with both and must be disabled there |
| Recommended allowlist switch | T2 egress allowlist | Narrows to GitHub's published default list | Hosts added on top of it |
| `deniedUrls` (Copilot CLI) | T2 egress allowlist | Listed URLs/domains: **denial takes precedence** | Egress via a shell command if the sandbox is off |
| `allowedUrls` (Copilot CLI) | - (loosening) | Nothing; it removes prompting. Supports exact URLs, domain patterns, wildcard subdomains | A bare `*` here defeats the point |
| `sandbox.enabled` (Copilot CLI, default `false`) | T1 OS sandbox | Microsoft eXecution Container: Seatbelt (macOS), Bubblewrap (Linux), ProcessContainer (Windows). By default read/write at and below CWD; unselecting "Include working directory" blocks `.git`; individual paths can be marked Denied; network can be fully isolated or restricted to block local network; macOS **keychain access is off by default** | Reads inside the CWD subtree. **[UNVERIFIED: exact `sandbox.*` key names beyond `sandbox.enabled`. Run `copilot help sandbox` to enumerate.]** |
| `permissions.disableBypassPermissionsMode: "disable"` | T4 harness deny rule | `--allow-all` / `--yolo` / `--allow-all-tools` | **[UNVERIFIED whether it survives a CLI `--yolo` when set at repo level; the cascade table puts flags above repo settings, but the setting's stated purpose implies it should hold.]** |
| `--deny-tool 'Kind(argument)'` | T4 harness deny rule | Verbatim: **"Deny rules always take precedence over allow rules, even when `--allow-all` is set or a matching approval has been saved in `permissions-config.json`."** | Session-only: not persisted to `permissions-config.json` |
| `permissions-config.json` approvals | - (grant store) | Nothing; it grants | A committed or inherited file with `{"kind":"write"}` or `{"kind":"mcp","toolName":null}` is a finding |
| `trustedFolders` in `config.json` | T4 harness deny rule | Untrusted directories | Auto-managed; not repo-assertable |
| `.claude/settings.json` `disableAllHooks` | T5 hook | All hooks under both Claude Code and Copilot CLI | Hooks are also the repo-side RCE surface: a committed `hooks` block runs under Copilot CLI |
| `copilot-instructions.md` | T7 instruction file | Nothing; steering only | Any tool call |
| `askUser` (default `true`) | - | Agent asking clarifying questions | - |

## Rule semantics you must get right

1. **Content exclusion is settings-UI only and does not apply to agent mode.** It is not a repo file, so a repo scan can never confirm it. Do not score a repo as protected because someone mentions content exclusion.
2. **Content exclusion syntax** (in the "Repositories and paths to exclude" box):
   ```yaml
   # files anywhere
   "*":
     - "/path/to/file"

   # files in a specific repo
   REPOSITORY-REFERENCE:
     - "/PATH/TO/DIRECTORY/OR/FILE"
     - "/PATH/TO/DIRECTORY/OR/FILE"
   ```
3. **`permissions.disableBypassPermissionsMode: "disable"` is the key hardening knob**: it neuters `--allow-all` / `--yolo`. Setting it in `.github/copilot/settings.json` makes it repo-enforced, subject to the cascade caveat above.
4. **Deny always wins in Copilot CLI**: both `deniedUrls` over `allowedUrls`, and `--deny-tool` over `--allow-tool`, saved approvals, and `--allow-all`. This is the opposite of OpenCode's last-match-wins.
5. **`permissions-config.json` is a grant store, not a policy file.** Structure:
   ```json
   {
     "locations": {
       "/absolute/path/to/repo": {
         "tool_approvals": [
           { "kind": "commands", "commandIdentifiers": ["git:*"] },
           { "kind": "write" },
           { "kind": "mcp", "serverName": "github-mcp-server", "toolName": null }
         ],
         "allowed_directories": ["/absolute/directory/paths"]
       }
     }
   }
   ```
   `kind` values: `commands` (needs `commandIdentifiers`), `read`, `write`, `mcp` (`serverName` + `toolName`, `null` = all tools on that server), `mcp-sampling`, `memory`, `custom-tool`, `extension-management`, `extension-permission-access`.
6. **Command matching is literal except for a trailing `:*`.** `git status` matches only `git status`, not `git status --short`. `git:*` matches `git`, `git status`, `git push` but **not** `gitea`. `gh pr:*` matches `gh pr view` but not `gh repo view`. `allowed_directories` must be absolute with symlinks resolved; case-insensitive on Windows; UNC paths blocked unless extended-length.
7. **Session flags take `Kind(argument)` patterns**: `copilot --allow-tool 'shell(git:*)' --deny-tool 'shell(git push)'`, `--deny-tool='My-MCP-Server(tool_name)'`. They are session-only. Exception: URL domain approvals persist to `allowedUrls` in `settings.json`. `/reset-allowed-tools` revokes session permissions and clears saved approvals for the location.
8. **GitHub's own warning on the permissive flags**, verbatim: "It is strongly recommended that you only use these options in an isolated environment. You should never use an alias to apply one of these options every time you start Copilot CLI."
9. **`.claude/settings.json` in a repo affects Copilot CLI**, including `hooks`. Any cross-harness scan must treat a Claude hooks block as a Copilot finding too.
10. **The firewall is incompatible with self-hosted and Windows runners** and must be disabled there, a real hardening trade-off requiring compensating network controls.
11. `.github/copilot/settings.local.json` is the personal-override layer and belongs in `.gitignore`.

## Detection checklist

**Repo-visible:**

| Check | Severity | Where to look |
|---|---|---|
| Repo docs, aliases, scripts, or CI invoking `copilot --allow-all`, `--yolo`, or `--allow-all-tools` with no container | Critical | `README*`, `Makefile`, `package.json`, `.github/workflows/**`, shell aliases in dotfiles committed to the repo |
| `COPILOT_AGENT_FIREWALL_ALLOW_LIST` set to a broad or wildcard value (replaces the default list) | Critical | repo/org Actions variables; workflow files |
| Committed `permissions-config.json` granting `{"kind":"write"}` or `{"kind":"mcp","toolName":null}` blanket approvals | Critical | anywhere in the repo, `.github/copilot/` |
| `.claude/settings.json` `hooks` block (executes under Copilot CLI as well as Claude Code) | Critical | `.claude/settings.json`, `.claude/settings.local.json` |
| `allowedUrls` containing a bare `*` | Critical | `.github/copilot/settings.json` |
| `.github/copilot/settings.json` absent, or present without `permissions.disableBypassPermissionsMode: "disable"` | High | `.github/copilot/` |
| `sandbox.enabled` not `true` (default is `false`) | High | `.github/copilot/settings.json` |
| `deniedUrls` empty | High | `.github/copilot/settings.json` |
| `.github/workflows/copilot-setup-steps.yml` with over-broad `permissions:` for `GITHUB_TOKEN`, or installing unvetted tooling | High | that workflow |
| `.github/copilot/settings.local.json` not in `.gitignore` | Medium | `.gitignore` |
| `mcp-config.json` committed with servers granting blanket tool access | Medium | repo tree |
| `.claude/settings.json` does not set `disableAllHooks` where the repo intends no hooks | Medium | `.claude/settings.json` |
| `.gitignore` does not cover secret patterns: the only repo-visible signal, since content exclusion is settings-side | Medium | `.gitignore` |
| `autoUpdate: true` left on in a locked-down environment | Low | `.github/copilot/settings.json` |

**Must verify out-of-band** (GitHub settings UI; no repo file can assert these):

| Check | Severity | Where to look |
|---|---|---|
| Coding agent **Internet access**: firewall not Enabled, or Recommended allowlist not Enabled | Critical | Settings → Copilot → Internet access (org, then repo if "let repositories decide") |
| Self-hosted or Windows runners in use → firewall is necessarily off; compensating network controls needed | Critical | `copilot-setup-steps.yml` runner label + firewall settings |
| **Content exclusion** not configured for secret paths | High, but annotate coverage: no Edit/Agent mode, no documented CLI or coding-agent coverage, no symlinks, no remote filesystems | Settings → Copilot → Content exclusion (repo / org / enterprise) |
| `~/.copilot/permissions-config.json` carrying blanket `write` / `mcp` `toolName: null` approvals for this repo's absolute path | High | user config dir (`$COPILOT_HOME`, default `~/.copilot`) |
| `~/.copilot/settings.json` not setting `permissions.disableBypassPermissionsMode` or `sandbox.enabled` | High | user config |
| `~/.copilot/config.json` `trustedFolders` containing unexpected paths | Medium | user config |
| Sandbox configured with "Include working directory" left on where `.git` access should be blocked, or macOS keychain access enabled | Medium | `copilot help sandbox`; sandbox settings |
| `~/.copilot/mcp-config.json` servers not needed by this repo | Medium | user config |

## Hardened baseline

### `.github/copilot/settings.json`: the repo-committable Copilot CLI surface

```json
{
  "permissions": {
    "disableBypassPermissionsMode": "disable"
  },
  "sandbox": {
    "enabled": true
  },
  "allowedUrls": [
    "https://github.com",
    "https://*.githubusercontent.com",
    "https://registry.npmjs.org"
  ],
  "deniedUrls": [
    "http://169.254.169.254",
    "http://metadata.google.internal",
    "http://localhost",
    "http://127.0.0.1"
  ],
  "askUser": true,
  "autoUpdate": false
}
```

Add to `.gitignore`:

```
.github/copilot/settings.local.json
```

### `~/.copilot/settings.json`: user level, same keys, so unhardened repos still land closed

```json
{
  "permissions": {
    "disableBypassPermissionsMode": "disable"
  },
  "sandbox": {
    "enabled": true
  },
  "allowedUrls": [],
  "deniedUrls": [
    "http://169.254.169.254",
    "http://metadata.google.internal"
  ]
}
```

### Content exclusion: **settings UI only, cannot be committed**

Paste into Settings → Copilot → Content exclusion, "Repositories and paths to exclude":

```yaml
"*":
  - "/.env"
  - "/.env.*"
  - "/**/*.pem"
  - "/**/*.key"
  - "/**/id_rsa*"
  - "/**/.netrc"
  - "/**/.npmrc"
  - "/secrets/**"
```

State in the report that this provides **no agent-mode protection** and cannot be verified from the repo.

### Coding agent firewall: settings UI only

Settings → Copilot → Internet access: **Enable firewall = on**, **Recommended allowlist = on**. If extra hosts are genuinely needed, add them in the UI rather than resurrecting `COPILOT_AGENT_FIREWALL_ALLOW_LIST` (which *replaces* the default list); `COPILOT_AGENT_FIREWALL_ALLOW_LIST_ADDITIONS` is the additive legacy form.

**Ignored / not settable from repo scope:** content exclusion, the firewall toggles, org-level Internet access policy, `trustedFolders`, and `permissions-config.json` (a user-side grant store; never commit one). Note also that **environment variables and CLI flags sit above `.github/copilot/settings.json`** in the cascade, so every repo-level key above is a default, not a guarantee.

## Verify at runtime

- `copilot help sandbox`: enumerates the actual `sandbox.*` keys, which the docs do not list.
- `--config-dir=DIRECTORY` / `$COPILOT_HOME`: confirm which config dir is live before reading `~/.copilot/*`.
- Inspect the grant store for this repo: read `~/.copilot/permissions-config.json` and look up the repo's absolute path under `locations`. Run `/reset-allowed-tools` in-session to clear saved approvals for the location.
- Test deny precedence: `copilot --allow-all --deny-tool 'shell(env)'` and confirm `env` is still refused.
- Test the bypass kill switch: with `disableBypassPermissionsMode: "disable"` in place, launch with `--yolo` and confirm prompting still occurs (this is the **[UNVERIFIED]** cascade interaction; resolve it empirically before relying on it).
- Coding agent firewall: check the agent session logs for blocked-host entries, and compare against <https://docs.github.com/en/copilot/reference/copilot-allowlist-reference>.
- Cross-harness: `cat .claude/settings.json` and confirm no `hooks` block, or that `disableAllHooks` is set.

## Sources

- <https://docs.github.com/en/copilot/concepts/context/content-exclusion>
- <https://docs.github.com/en/copilot/how-tos/configure-content-exclusion/exclude-content-from-copilot>
- <https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/customize-the-agent-firewall>
- <https://docs.github.com/en/copilot/reference/copilot-allowlist-reference>
- <https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment>
- <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools>
- <https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/configuring-local-sandbox-settings>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/configure-copilot-cli>
