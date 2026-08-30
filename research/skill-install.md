# Where Agent Skills install, and which harnesses honour `disable-model-invocation`

Verified against: **2026-08-30**. Primary sources only (vendor docs / vendor GitHub repos), cited inline. Anything not confirmed from a primary source is marked **[UNVERIFIED]**.

## Summary

| Harness | Supports `SKILL.md` | User-level path | Project-level path | Honours `disable-model-invocation` |
|---|---|---|---|---|
| Claude Code | ✅ (origin) | `~/.claude/skills/<name>/SKILL.md` | `.claude/skills/<name>/SKILL.md` | ✅ |
| Cursor | ✅ | `~/.cursor/skills/`, `~/.agents/skills/` | `.cursor/skills/`, `.agents/skills/` | ✅ |
| OpenAI Codex CLI | ✅ | `$HOME/.agents/skills` | `.agents/skills` (cwd, parent, repo root) | ⚠️ different mechanism (`allow_implicit_invocation`) |
| OpenCode | ✅ | `~/.config/opencode/skills/`, `~/.claude/skills/`, `~/.agents/skills/` | `.opencode/skills/`, `.claude/skills/`, `.agents/skills/` | ❌ **field ignored** |
| GitHub Copilot CLI | ✅ | `~/.copilot/skills`, `~/.agents/skills` | `.github/skills`, `.claude/skills`, `.agents/skills` | ❌ not documented |
| Gemini CLI | ✅ | `~/.gemini/skills/`, `~/.agents/skills/` | `.gemini/skills/`, `.agents/skills/` | ❌ not documented |
| Amp | ✅ | `~/.config/agents/skills/`, `~/.agents/skills/`, `~/.config/amp/skills/`, `~/.claude/skills/` | `.agents/skills/`, `.claude/skills/` | ❌ not documented |
| Kiro | ✅ | `~/.kiro/skills/` | `.kiro/skills/<name>/SKILL.md` | ❌ not documented |

All eight read `~/.claude/skills` / `.claude/skills` **or** the cross-vendor `.agents/skills` convention, so a skill dropped in either is portable by default — and only two of eight honour the field that stops the model auto-running it.

## 1. Claude Code — <https://code.claude.com/docs/en/skills>

Discovery table, verbatim: Enterprise (managed settings dir), Personal `~/.claude/skills/<skill-name>/SKILL.md`, Project `.claude/skills/<skill-name>/SKILL.md`, Plugin `<plugin>/skills/<skill-name>/SKILL.md`. Project skills also load from every parent dir up to the repo root, from `--add-dir` dirs, and lazily from nested `.claude/skills/` once Claude touches a file in that subtree.

**`disable-model-invocation`** — "Set to `true` to prevent Claude from automatically loading this skill… Also prevents the skill from being preloaded into subagents. As of v2.1.196, also prevents the skill from running when a scheduled task fires with the skill as its prompt." The matrix gives: you can invoke = Yes, Claude can invoke = No, "Description not in context". Enforcement is hard, not advisory: "If Claude tries anyway, Claude Code blocks the call and instructs it not to reproduce the deploy steps another way." Also: "By default, Claude can invoke any skill that doesn't have `disable-model-invocation: true` set"; "To keep Claude from invoking it through the Skill tool, set `disable-model-invocation: true`." The settings equivalent, for files you don't want to edit, is `skillOverrides` set to `"user-invocable-only"`.

*Invocation by another skill* is not stated in those words. Skill-to-skill invocation goes through the same Skill tool the above blocks, and an open bug confirms subagents cannot invoke such a skill even when the parent names it (<https://github.com/anthropics/claude-code/issues/43809>) — but the literal case is **[UNVERIFIED]**.

**Reload / verify** — `/reload-skills` **is not a real command**; it appears in neither the skills page nor the commands reference (<https://code.claude.com/docs/en/commands>). What is real: live change detection ("Claude Code watches skill directories… picks up the change within the current session, without a restart" for `~/.claude/skills/`, project `.claude/skills/`, and `--add-dir` skill dirs); restart only when you create a *top-level skills directory that didn't exist when the session started*; `/skills`, the menu that lists skills and writes `skillOverrides` ("press `Space` to cycle states, then `Esc` to save to `.claude/settings.local.json`"); `/context`, which groups them; and `/reload-plugins`, needed for plugin-shaped skill folders since live detection "covers `SKILL.md` text only". Nested skills "don't appear in autocomplete and can't be invoked by name" until Claude touches that subtree.

**Symlinks — confirmed supported.** "A `<skill-name>` entry in the enterprise, personal, or project locations can be a symlink to a directory elsewhere on disk. Claude Code follows the symlink and reads `SKILL.md` from the target directory, and if the same target is reachable from more than one location, Claude Code loads the skill once." Plugin skills handle symlinks differently. So `ln -s /path/to/checkout ~/.claude/skills/<name>` is documented to work.

## 2. Cursor — <https://cursor.com/docs/skills>

"Skills are automatically loaded from these locations": `.agents/skills/`, `.cursor/skills/`, `~/.agents/skills/`, `~/.cursor/skills/` — project and user level both. Frontmatter beyond `name`/`description`: `paths`, `disable-model-invocation`, `icon`, `color`, `metadata`. **Honours the field**: "Set `disable-model-invocation: true` to make a skill behave like a traditional slash command, where it is only included in context when you explicitly type `/skill-name` in chat."

## 3. OpenAI Codex CLI — <https://learn.chatgpt.com/docs/build-skills>

(Redirect target of <https://developers.openai.com/codex/skills>.) Load paths: `$CWD/.agents/skills`, `$CWD/../.agents/skills`, `$REPO_ROOT/.agents/skills`, `$HOME/.agents/skills`, `/etc/codex/skills`. Required frontmatter: `name`, `description`. Codex does **not** read `disable-model-invocation`; its equivalent is `allow_implicit_invocation` (default `true`) in a sidecar `agents/openai.yaml` in the skill directory. Set it `false` and "the model won't automatically select the skill based on user prompts", while explicit `$skill` still works — so a SKILL.md carrying only `disable-model-invocation` stays model-invocable here. `~/.codex/skills/` is widely repeated by third parties but is **[UNVERIFIED]**: not in the official path list.

## 4. OpenCode — <https://opencode.ai/docs/skills/>

Project: `.opencode/skills/<name>/SKILL.md`, `.claude/skills/<name>/SKILL.md`, `.agents/skills/<name>/SKILL.md`. User: `~/.config/opencode/skills/<name>/SKILL.md`, `~/.claude/skills/<name>/SKILL.md`, `~/.agents/skills/<name>/SKILL.md`.

**Does not honour the field.** "Only these fields are recognized: `name` (required), `description` (required), `license` (optional), `compatibility` (optional), `metadata` (optional, string-to-string map)" and "Unknown frontmatter fields are ignored." The feature request confirms runtime behaviour: "Currently, OpenCode appears to ignore this field. Skills with `disable-model-invocation: true` are still visible to the model" (<https://github.com/anomalyco/opencode/issues/11972>). Compensating control: per-skill permissioning of the `skill` tool in `opencode.json` — `allow` ("Skill loads immediately"), `ask` ("User prompted for approval before loading"), `deny` ("Skill hidden from agent, access rejected") — or disabling the `skill` tool entirely, which removes the `<available_skills>` section. There is no `skills` key in the documented `opencode.json` schema (<https://opencode.ai/docs/config/>); control is via the `skill` tool's permissions.

## 5. GitHub Copilot CLI — <https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills>

Project: `.github/skills`, `.claude/skills`, or `.agents/skills`. Personal: `~/.copilot/skills` or `~/.agents/skills`. Documented frontmatter: `name`, `description` (both required), `license`, `allowed-tools`. **No `disable-model-invocation`, no auto-invocation control**: "Copilot will decide when to use your skills based on your prompt and the skill's description." Reload with `/skills reload` in-session, or restart.

## 6. Gemini CLI — <https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/using-agent-skills.md>

User `~/.gemini/skills/` or the `~/.agents/skills/` alias; workspace `.gemini/skills/` or the `.agents/skills/` alias. Precedence lowest→highest: built-in, extension, user, workspace. `SKILL.md` may sit at the skills-dir root or one level deep (<https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills.md>). **No `disable-model-invocation`** and no per-skill manual-only mode documented; the only controls are the whole-skill kill switch `/skills disable <name>` and a user consent prompt before injection.

## 7. Amp — <https://ampcode.com/docs/customize/skills>

Checked in precedence order: `~/.config/agents/skills/`, `~/.agents/skills/`, `~/.config/amp/skills/`, then `.agents/skills/` and `.claude/skills/` in the project and parent directories, then `~/.claude/skills/`, `~/.claude/plugins/cache/`, and any dirs in `amp.skills.path`. Frontmatter: `name` (required, must match the directory), `description` (required), `mcpServers` (optional). **No `disable-model-invocation`**: "Amp lists every discovered skill for the model", which "sees each skill's `name` and `description` and uses them to decide when to load it." Amp reads `~/.claude/skills/`, so a Claude Code personal skill is live in Amp with no extra step.

## 8. Kiro — <https://kiro.dev/docs/skills/>

Workspace `.kiro/skills/<Skill Name>/SKILL.md`; global `~/.kiro/skills/`. Frontmatter: `name`, `description` (required), `license`, `compatibility`, `metadata` — the base spec, **no `disable-model-invocation`** and no documented per-skill auto-activation switch. Kiro's capability permissions do include a `skill` capability alongside `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, `mcp`, `subagent`, `power`, `context`, `diagnostics`, `sandbox_network`, taking `allow`/`ask`/`deny` with deny-overrides (<https://kiro.dev/docs/permissions/>). Permissions live at `~/.kiro/settings/permissions.yaml` (user) and `~/.kiro/workspace-roots/<hash>/permissions.yaml` (workspace) — outside the repo, so not committable. Kiro also documents that "there is no isolation between individual skills."

## What we could not verify

- **Claude Code, skill-invoking-skill.** Docs cover model invocation and subagent preload, not skill A's body telling Claude to run skill B. The Skill-tool block makes it near-certain; the phrase is not in the docs.
- **`~/.codex/skills/`** as a real Codex CLI load path — third-party guides say so, the official list omits it.
- **Whether Cursor's `disable-model-invocation` is enforced or advisory** — Cursor documents its effect on context inclusion, never that the harness *blocks* a model attempt the way Claude Code explicitly does.
- **What Kiro's `skill` capability gates** (any skill load vs. per-skill match patterns) — listed, not specified.
- **Symlink following in harnesses other than Claude Code.** None of the other seven document it either way.
- **Copilot CLI skill definition format.** A third-party source claims a `skill.json`/`skill.yaml` is required alongside `SKILL.md`; GitHub's own page describes `SKILL.md` alone, so that claim is rejected.
