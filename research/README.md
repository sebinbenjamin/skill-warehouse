# Research

Source material, not guidance. These are the investigation notes behind the `agent-permissions` references, recorded as they were found on 2026-08-30 and left unedited since.

Copy configuration from [`agent-permissions/references/`](../agent-permissions/references/), which is the corrected version that is kept current.

| File | Became |
| :-- | :-- |
| `agent-permissions/threat-model.md` | `references/controls.md`, `references/checklist.md`, `references/secret-scan.md` |
| `agent-permissions/claude-code.md` | `references/claude-code.md` |
| `agent-permissions/codex.md` | `references/codex.md` |
| `agent-permissions/other-harnesses.md` | `references/{opencode,gemini-cli,cursor,copilot,other-harnesses}.md` |
| `skill-install.md` | the install and cross-harness sections of the top-level `README.md` |

## Why it is kept

Each claim here carries an inline source URL, and each file records what could not be verified against a primary source. The references compress that to a short source list per page, so this is where an audit trail of *why a rule exists* survives.

## Known defects

- `agent-permissions/codex.md`: the three baseline `config.toml` / `requirements.toml` snippets are invalid TOML as written. Top-level keys appear after table headers and bind to the wrong table. Corrected in `references/codex.md`. The file carries the same caution at the top.
- Product behaviour has moved since the snapshot date; the `Verified against:` lines in the references are the ones kept current.
