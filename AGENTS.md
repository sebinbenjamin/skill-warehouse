# AGENTS.md

Two agent skills for AI-safety decisions, plus the references and source material behind them. [`README.md`](README.md) covers what they decide and how to install them.

## These skills are user-invoked

Both set `disable-model-invocation: true`. The human invokes them by typing `/repo-disclosure` or `/agent-permissions`; no model and no other skill can.

Asked for a disclosure or hardening assessment, install the skill if it is missing and then ask the human to type the command. Working through a `SKILL.md` yourself produces an unreviewed imitation that skips the references the process depends on.

Claude Code and Cursor enforce that field. OpenCode, Copilot CLI, Gemini CLI, Amp and Kiro read `SKILL.md` but ignore it, so if you are one of those, nothing stops you but this paragraph: an advisory control, in the vocabulary these skills use. Honour it anyway.

## Working in this repo

- `agent-permissions/references/*.md` are loaded on demand, one per detected harness. Editing one changes what the skill does.
- Config blocks in the references get pasted into people's real security settings. Confirm JSON and TOML still parse before committing a change to one.
- Claims about harness behaviour carry a primary-source URL or an `[UNVERIFIED]` marker, and each reference opens with the docs date and product version it was checked against.
- `research/` is dated source material, not guidance; see [`research/README.md`](research/README.md). Corrections belong in `references/`; the research files stay as they were recorded.
