# skill-warehouse

Agent skills for the safety decisions you make *before* pointing an AI coding agent at a repository.

Two questions, in order. May this code reach this provider at all? And once it does, how narrowly is the agent confined?

## Skills

| Skill | Decides | Reach for it when |
| :-- | :-- | :-- |
| [`repo-disclosure`](repo-disclosure/SKILL.md) | Whether a repository may be disclosed to an AI provider that can retain or train on what it receives. | You are about to use a new provider, tier, or model on a repo you do not fully own. |
| [`agent-permissions`](agent-permissions/SKILL.md) | What an agent harness may read, run, and reach from this repo and machine, and what enforced limits to apply. | You are setting up a harness, enabling auto mode, or letting an agent run unattended. |

Both are user-invoked. They cost nothing in context, and Claude Code blocks the model from firing them itself. Type `/repo-disclosure` or `/agent-permissions`. [Five of the eight harnesses that can load them ignore that setting.](#other-harnesses)

A run is not free. Before it scans, `repo-disclosure` sizes the repository, states a token estimate, and asks which approved models should read and which should decide. Where the harness has subagents, the reading goes to them and only the findings come back.

`agent-permissions` reads the config of the harness you actually run (Claude Code, Codex CLI, OpenCode, Gemini CLI, Cursor, GitHub Copilot, Aider, Cline, Roo Code, Amp, or Kiro) and loads a per-harness reference only for the ones it finds.

## Install

Claude Code discovers skills in `~/.claude/skills/` and, per project, `.claude/skills/`. An entry there may be a symlink. Claude Code follows it and reads `SKILL.md` from the target, so a `git pull` in the checkout updates the installed skill:

```bash
git clone https://github.com/sebinbenjamin/skill-warehouse
cd skill-warehouse
mkdir -p ~/.claude/skills
ln -s "$PWD/repo-disclosure"   ~/.claude/skills/repo-disclosure
ln -s "$PWD/agent-permissions" ~/.claude/skills/agent-permissions
```

Copy instead where symlinks are awkward (Windows needs Developer Mode or an elevated shell), and re-copy after each `git pull`:

```bash
cp -r repo-disclosure agent-permissions ~/.claude/skills/
```

Swap `~/.claude/skills/` for `.claude/skills/` to scope them to a single project.

Verify with `/skills`, which lists what loaded. Claude Code watches skill directories and picks up changes without a restart; you only need to restart if `~/.claude/skills/` did not exist when the session started.

### Other harnesses

`agent-permissions` *audits* eleven harnesses, and every harness surveyed can also *run* it: all read `SKILL.md` from either `.claude/skills/` or the cross-vendor `.agents/skills/` convention. Keeping the checkout in `~/.agents/skills/` and symlinking it into `~/.claude/skills/` reaches all of them at once.

Running them elsewhere loses a protection. Both skills set `disable-model-invocation: true`, but **only Claude Code and Cursor honour it**. OpenCode, Copilot CLI, Gemini CLI, Amp and Kiro ignore the field outright, and Codex CLI wants `allow_implicit_invocation: false` in a sidecar `agents/openai.yaml` instead. So in six of the eight, the model can start an assessment on its own unless you configure it otherwise. Use whatever control the harness does offer: OpenCode gates the `skill` tool per skill in `opencode.json`, Kiro has a `skill` capability, Gemini CLI has `/skills disable <name>`.

Per-harness paths and citations: [`research/skill-install.md`](research/skill-install.md).

## Enforced, advisory, inert

Both skills rank controls by enforceability, not by how protective they look:

| | Tier | Enforced by |
| :-- | :-- | :-- |
| **Enforced** | T1 OS sandbox · T2 egress allowlist · T3 credential scrub · T4 harness deny rule · T5 hook | Outside the model: the OS, the network, or the harness's rule engine |
| **Advisory** | T6 ignore file · T7 instruction file | The model choosing to comply |

A model cannot separate instructions from data, so anything that depends on it obeying is not a control. A line in `AGENTS.md` saying "never read `.env`" stops nothing adversarial; `.cursorignore` does not cover the agent's terminal, and its vendor says so. Both skills report which tier is doing the work, and treat an advisory-only protection as unprotected.

The other failure is inert config: a key placed in a scope the harness ignores, a policy tier that was never implemented, a rule written against a tool name that is never consulted. It is worse than absent config, because someone believes it works.

## Layout

```
repo-disclosure/SKILL.md          the disclosure decision
repo-disclosure/references/       sizing commands and the briefs pasted into worker subagents
agent-permissions/SKILL.md        the hardening decision
agent-permissions/references/     shared vocabulary, graded checklist, scan commands,
                                  and one hardening reference per harness
research/                         the dated investigation behind the references
```

`references/` is the maintained guidance; `research/` is the citation trail it was built from, recorded 2026-08-30 and unedited since. [`research/README.md`](research/README.md) maps one to the other and lists its known defects.

## Staleness

Every harness reference opens with a `Verified against:` line naming the docs date and product version it was checked against. Harness security behaviour moves fast, and several findings here are version-gated. Re-check that line against the vendor's current docs before relying on a specific key, and treat anything marked `[UNVERIFIED]` as needing a test on your own machine.

[MIT licensed](LICENSE).
