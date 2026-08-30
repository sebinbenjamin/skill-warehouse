---
name: agent-permissions
description: Audit what an agent harness may read, run, and reach from this repo and machine, and propose enforced limits.
disable-model-invocation: true
license: MIT
metadata:
  version: "1.0.0"
  agent-permissions.audience: developers
  agent-permissions.purpose: ai-data-safety
---

# Agent permissions

Decide whether the harness setup in this repo and on this machine is safe to run, and produce the configuration that makes it so. This is a **hardening** decision, not a disclosure decision — `repo-disclosure` decides *whether* the project may reach the provider; this skill decides *how narrowly the agent is confined* once it does. The question is:

> If the model follows an injected instruction, or simply does the obvious thing, what can it read, run, or send that the owner would not want in a retained transcript or on an attacker's server — and what enforced control stops it?

The report carries names, paths, and patterns; secret and personal values stay out of it.

## Vocabulary

Read `references/controls.md` before assessing; its terms carry through every step.

- **Reach** — everything the agent can read, run, or contact during the intended workflow: the worktree including ignored and untracked files, Git history, the home directory, the process environment, connected tools (MCP servers, ambient-auth CLIs), the network, and prior transcripts. Same definition as in `repo-disclosure`.
- **Enforced** control — tiers T1–T5 (OS sandbox, egress allowlist, credential scrub, harness deny rule, hook): enforced outside the model. **Advisory** — T6–T7 (ignore files, instruction files): a prompt, not a boundary. A finding is *protected* only by an enforced control.
- **Inert** — config that is present and looks protective but enforces nothing: a key placed in a scope that ignores it, a policy tier the harness has not implemented, a rule written against a tool name that is never consulted, a mis-anchored path, a hook whose script is missing or exits non-blocking, POSIX paths on a Windows host. Inert config is *unprotected*, and worse than absent config, because someone believes it works (check C20).
- **Gate** — an `ask` rule or approval prompt that keeps a human in the loop for a consequential action. Prefer a gate to a deny wherever the action has legitimate uses.
- **Disclosure** vs **exfiltration** — data reaching the provider through ordinary operation, versus data reaching a third party through an attack. Read scope governs the first; network isolation and gates govern the second. A sandbox alone does nothing for disclosure.

## Assessment target

Establish before scanning:

- the harnesses in use — detect from the surfaces below, then confirm with the user which are actually run against this repo:

  | Harness | Detect from | Reference |
  | :-- | :-- | :-- |
  | Claude Code | `.claude/`, `CLAUDE.md`, `.mcp.json`, `~/.claude/` | `references/claude-code.md` |
  | Codex CLI | `.codex/`, `AGENTS.md`, `~/.codex/` | `references/codex.md` |
  | OpenCode | `opencode.json(c)`, `.opencode/`, `~/.config/opencode/` | `references/opencode.md` |
  | Gemini CLI | `.gemini/`, `.geminiignore`, `~/.gemini/` | `references/gemini-cli.md` |
  | Cursor | `.cursor/`, `.cursorignore`, `~/.cursor/` | `references/cursor.md` |
  | GitHub Copilot | `.github/copilot/`, `.github/copilot-instructions.md`, `~/.copilot/` | `references/copilot.md` |
  | Aider · Cline · Roo · Amp · Kiro | `.aider*`, `.clineignore`, `.rooignore`, `.kiro/`, `.kiroignore` | `references/other-harnesses.md` |

- the host platform — some sandboxes do not exist on native Windows, where the whole sandbox block is inert
- the session mode: interactive, headless (`-p`, SDK), or CI — headless modes skip trust dialogs
- the provider tier and whether it retains or trains (unknown → assume yes; this escalates every severity by one level per `references/checklist.md`)
- who can change what: a solo developer edits user settings; a team may have managed/org settings that a repo file cannot override

Done when each item is known or explicitly assumed, and the list of harnesses to assess is agreed.

## Process

### 1. Inventory reach

Run `references/secret-scan.md` end to end: worktree and history secret scans, on-disk secret files, git plumbing, symlinks, env-var names, home credential stores, ambient-auth CLIs, cloud metadata, sibling repos, yolo flags in scripts and shell profiles.

Done when every command in the reference has run or been explicitly skipped with a reason, and every finding is recorded with a check id from sections A, B, and D of `references/checklist.md`.

### 2. Read each harness configuration

For each harness in scope, load its reference from the table above and walk its detection checklist against every config surface it lists — repo files, user files, managed/system files, and vendor-side settings that can only be verified out of band.

Cross-harness surfaces count for every harness that reads them: `AGENTS.md` is shared; Copilot CLI reads `.claude/settings.json` hooks; a repo's hooks, `env` blocks, and MCP definitions execute under any harness that loads that file.

Hunt for **inert** config on every surface, and record each instance as a finding.

Done when every check in each harness reference and in sections C–F of `references/checklist.md` has a result: pass, finding, or not verifiable from here.

### 3. Classify each finding

For each finding record the severity from the checklist (escalated where the target calls for it), the control that protects it *now* and its tier, or `unprotected`, and the enforced control that would close it. An advisory-only protection is `unprotected`. A secret that has been deleted but not rotated stays open.

Done when every finding carries severity, current tier, and closing control.

### 4. Decide

Apply the verdict rule in `references/checklist.md`. Give one verdict per harness and one overall — the most restrictive of them.

Done when the verdicts are consistent with the findings and no Critical is closed by an advisory control.

### 5. Propose the hardened configuration

Produce, for each harness, the complete config files that close the findings — not fragments. Start from the harness reference's hardened baseline and fit it to this repo's real workflow (package registries it needs, hosts the build contacts, commands that run routinely), so the gates fire for the consequential and not for the routine. For each file state:

- the exact path and scope (repo-committed, user, managed) — a key in a scope that ignores it is inert, not a fix
- which findings it closes and at which tier
- what it breaks, using the trade-off table in `references/controls.md`, and the mitigation
- what remains open and why (no sandbox on this platform, vendor setting that must be changed in a UI, credential that must be rotated)

Steps only a human can take — rotating a credential, enabling a vendor firewall or privacy mode, opting out of training, installing a sandbox dependency, moving to WSL2 or a container — go in a numbered manual list with the exact location of the switch.

Write the proposals to the report. Apply them to the working tree or home directory only when the user asks; editing a harness's own configuration is exactly the kind of change the gate list says a human approves.

Done when every open finding maps to a proposed file, a manual step, or an explicitly accepted residual risk.

## Report format

```markdown
# Agent permissions assessment

**Overall verdict:** DO NOT RUN | HARDEN FIRST | RUN WITH CARE | HARDENED
**Per harness:** <harness: verdict>, …
**Assessed for:** <provider and tier, or the conservative training-eligible assumption>
**Host:** <OS, sandbox availability, session mode>
**Scope:** <repo, worktree, home directory, connected tools>
**Confidence:** High | Medium | Low

## Why
<the decisive findings, one short paragraph>

## Findings
| Check | Location | Severity | Protected by | Closes with |
<one row per finding; `unprotected` where only an advisory control applies — or `None found`>

## Inert configuration
<config present but not enforced, with the reason — or `None`>

## Not verifiable from here
<vendor-side settings, provider terms, managed policies that need out-of-band confirmation — or `None`>

## Proposed configuration
### <path> (<scope>)
<complete file contents>
Closes: <check ids and tiers>. Breaks: <trade-off and mitigation>.

## Manual steps
<numbered; each with the exact switch, rotation, or install — or `None`>

## Residual risk
<what stays open after everything above is applied, and why>

## Recommendation
<one direct operational recommendation>
```

Recommendation examples:

- Do not run any harness against this repository until the verified AWS key in history is rotated and the worktree `.env` is outside reach.
- Commit the proposed `.claude/settings.json`, apply the user-level file, and run inside WSL2 so the sandbox block is live; until then, treat the setup as RUN WITH CARE with no unattended sessions.
- The setup is hardened for interactive use; headless and CI runs need `--restricted` or an equivalent because trust dialogs never fire there.
