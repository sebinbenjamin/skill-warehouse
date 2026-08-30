# Sizing commands and worker briefs

A subagent cannot load this skill. `disable-model-invocation: true` blocks preload into subagents and blocks the Skill tool, so a worker told to "follow the repo-disclosure skill" has nothing to follow. Every dispatch pastes three blocks into the worker's prompt instead: the brief for its pass, the findings schema, and the data classes.

## Sizing commands

Run from the repo root, before any pass reads a file.

```bash
git ls-files | wc -l                                    # tracked files
du -sb --exclude=.git --exclude=node_modules --exclude=.venv \
       --exclude=vendor --exclude=target .              # worktree bytes in reach
git rev-list --count HEAD                               # commits
git count-objects -vH                                   # repo and pack size
du -sb */ | sort -rn | head -10                         # ten largest directories
git log -p | wc -c                                      # history bytes for the history pass
```

PowerShell equivalent for the worktree byte count where the Bash tool is unavailable (`-Exclude` filters leaf names and does not prune recursion, so filter on the full path): `(Get-ChildItem -Recurse -File | Where-Object FullName -notmatch '\\(\.git|node_modules|\.venv|vendor|target)\\' | Measure-Object Length -Sum).Sum`.

Estimate: **tokens ≈ bytes / 4** for text. Report the estimate per pass, not one total, since passes 2 to 4 cover the worktree and pass 5 covers `git log -p` bytes. Above roughly 200k tokens for a single pass, bound it: a commit range for history, a directory sample for the worktree, and say in the report which bound was used.

## Findings schema

A worker returns **citations**: what kind of thing, where it sits, what class it falls in. A citation names its target and never carries it, so the finished list can be read aloud in a room where the repository itself may not be discussed. The list is the worker's whole output, with no prose around it.

```
- type: secret | personal-data | infrastructure | client-material | internal-doc | licensed-third-party | commit-message | other
  location: <path[:line] or commit sha>
  class: RESTRICTED | CONFIDENTIAL | PRIVATE-OWNED | PUBLIC
  confidence: high | medium | low
  note: <one line characterising it>
```

`confidence` is the worker's read, not a decision; the parent session confirms or rejects each entry.

Paste this section with every brief. It is the output contract, so a brief that travels without it has none.

## Data classes for worker prompts

Paste this section with every brief. `SKILL.md` is authoritative and this copy follows it; both exist only because a worker cannot read that file.

- **PUBLIC**. Intentionally public: published open-source code, public documentation, synthetic examples, placeholder configuration. Compatible with a training-eligible provider on its own; local files, uncommitted changes, credentials, and connected tools can still make the working project unsafe.
- **PRIVATE-OWNED**. Non-public, wholly owned by the user, free of employer, client, collaborator, privacy, contractual, or licensing restriction (an unpublished personal project). Safe once the owner has authority to consent and accepts the provider's terms.
- **CONFIDENTIAL**. Non-public information whose disclosure would breach an employment, client, NDA, contractual, licensing, or security expectation: private company or client source; internal architecture, hostnames, infrastructure; non-public product plans, research, pricing, strategy; proprietary algorithms, business logic, datasets; security findings, incidents, operational procedures; internal tickets, meeting notes, support conversations; third-party licensed material not permitted for this use. Disclosable only with evidence that this provider/use is permitted. A file needs no `CONFIDENTIAL` label, and no credentials inside it, to be confidential.
- **RESTRICTED**. Exposure creates a direct security, privacy, regulatory, or account-access risk: passwords, API keys, tokens, session cookies, private keys, signing certificates, credential stores, production connection strings and configuration; cloud and package-registry credentials, Terraform state, Kubernetes configuration; real personal data (customer, candidate/student, employee, support, authentication, payment, regulated records) wherever it sits (dumps, exports, fixtures, logs, screenshots); live secrets present only in Git history. A confirmed restricted finding is **DO NOT USE** until it is outside the provider's reach. A possibly exposed credential gets a rotation or revocation recommendation; deletion alone leaves it live.

## Brief A, inventory reach

> You are inventorying what an AI provider could receive from this repository. Return citations in the findings schema, and nothing else.
>
> List every surface present in this repo from the reach list below, for the access mode named in your dispatch:
>
> - tracked source and documentation
> - untracked, ignored, hidden, generated, and local developer configuration files, and symlink targets
> - infrastructure definitions, deployment manifests, and database migrations
> - diffs, patches, and Git history
> - fixtures, exports, dumps, logs, screenshots
> - terminal, test, build, and debug output
> - environment variables and runtime configuration
> - issues, tickets, PRs, and internal documentation
> - anything behind connected tools: authenticated systems, cloud tooling, databases, email, calendars, support systems
>
> Dependency caches and generic build output are out of reach unless they hold project-specific or real data. A Git-ignored file is as reachable as a tracked one; a clean working tree proves nothing.
>
> ```bash
> git status --ignored --porcelain | head -50
> find . \( -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \
>   -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '*.tfstate*' -o -name '*.har' \
>   -o -name '.npmrc' -o -name '.netrc' -o -name 'serviceAccount*.json' -o -name '*credential*' \) \
>   -not -path '*/node_modules/*' -not -path './.git/*'
> find . -type l -not -path '*/node_modules/*' -exec ls -ld {} +
> ```
>
> A symlink pointing outside the repo is a finding. Give the link path and the target directory, and class it by what the target holds.

## Brief B, restricted data

> You are hunting RESTRICTED material in this repository for a disclosure assessment. Return citations in the findings schema, and nothing else. This is the pass with live secrets in front of it. Cite each one by file and pattern type, and let the value stay where it is, uncopied, including in your own reasoning.
>
> Run the scanners that are installed; if one is missing, say so in a `note` and continue with the rest:
>
> ```bash
> gitleaks dir -v --no-banner .
> trufflehog filesystem . --results=verified --no-update
> ```
>
> A `trufflehog` verified finding is a live credential: class `RESTRICTED`, confidence `high`, and note that it needs rotation, not deletion.
>
> Then list by hand what pattern scanners miss: fixtures, seed data, database dumps and exports, log files, `.har` captures, screenshots and recordings, and anything under a `test-data`, `sample`, `fixtures`, or `snapshots` path.
>
> For each candidate, judge placeholder against real. Placeholder markers: `example`, `changeme`, `xxx`, `dummy`, `test`, obviously invalid lengths or checksums, values already published in the repo's own documentation. Real markers: correct provider prefix and length, plausible hostnames and account ids, personal data with realistic name/email/phone/address variety rather than repeating dummies. When you cannot tell, report it with `confidence: low` and let the parent decide.

## Brief C, semantic confidentiality

> You are reading source and documentation for CONFIDENTIAL information a pattern scan cannot see. Return citations in the findings schema, and nothing else. Characterise each finding in one line of your own words rather than quoting it.
>
> Read the paths handed to you in this dispatch. Read them fully unless the dispatch says sample; if it says sample, name in each `note` what you sampled.
>
> For each file or project area, ask:
>
> > Would the owner reasonably object if this exact material were submitted to a provider allowed to retain or train on it?
>
> Look for: client or employer names and branding; internal hostnames, environments, and architecture; non-public product plans, pricing, research, or strategy; proprietary algorithms and business rules; security findings, incidents, and operational procedures; internal tickets, meeting notes, and support conversations; third-party material under a licence that may not permit this use.
>
> Ordinary-looking code counts. A file needs no confidentiality label, and no credentials in it, to be confidential. Report per path where the material is localised, and per project area where a whole directory shares one character.

## Brief D, Git history

> You are checking Git history for material that is no longer in the working tree but is still readable via `git log` and `git show`. Return citations in the findings schema, and nothing else, using the commit sha as the location. Stay inside the commit range given in your dispatch.
>
> ```bash
> git log --all --diff-filter=D --name-only <range>     # files deleted from the tree, still in history
> gitleaks git -v --no-banner .
> git log <range> --format='%s%n%b' | grep -Ein 'client|customer|password|credential|prod|internal|ticket|jira|incident|\.internal|\.corp'
> ```
>
> Append the path to the sha when the finding is a file. A secret that exists only in history is still `RESTRICTED`, because the provider can run `git log -p`. Deletion is not remediation; note rotation for anything that looks live.
>
> Commit messages are their own finding type: client names, internal hostnames, ticket ids, and incident descriptions leak from messages even when every diff is clean. Use `type: commit-message`.

## Inline fallback

For a harness with no in-session subagent, run passes 2 to 5 here, in this order, so cheap listings narrow the reading before it starts:

1. Sizing commands, then the model question. The question still fires. Where the harness sets a session model (Codex: `--profile`), the answer picks it; otherwise the answer only lands in `Read by:`.
2. Scanners and listings from briefs A, B, and D. These are command output, not file reads, and cost little.
3. Read in full: every documentation, configuration, fixture, migration, and infrastructure path, plus every path flagged in step 2.
4. Sample the rest, largest directories first from `du -sb */ | sort -rn`. Read entry points and one representative file per module rather than every file.

State the sampling in the report. `Unknowns` names the directories you sampled rather than read, and what a full read could still turn up. `Confidence` drops to Medium when you sampled any area in reach, and to Low when you skipped a large area or truncated the history range.

## Dispatch notes per harness

**Claude Code.** One Agent call per pass; independent passes can go in a single message and run in parallel. Set `model` per call: `"haiku"`, `"sonnet"`, or `"opus"`. The brief goes in `prompt` in full, with the data classes block and the findings schema, since the worker cannot load the skill.

```
Agent(subagent_type: "Explore", model: "haiku", prompt: "<brief + data classes + schema>")
```

Brief C on a large repo splits across several calls by directory; give each the paths it owns.

**OpenCode.** Subagents come from `.opencode/agents/<name>.md`, a repo file the user has to create. Ask them to create one before you dispatch, and offer this skeleton:

```markdown
---
mode: subagent
model: anthropic/claude-haiku-4-5
tools:
  write: false
  edit: false
---

<brief pasted here>
```

Agent files sit in the repo layer and their rules take precedence over the global `permission` block, so a file added for this assessment can widen permissions. Keep `write` and `edit` off, and offer to delete the file after the run.

**Codex CLI.** No in-session subagent. `--profile` names a separate config file that sets `model` for the **whole session**, not for one pass, so switching to a cheap model for reading also puts the verdict on that model. Either accept that and say so in `Read by:`, or run the inline fallback on the session's main model. Since 0.134.0 a profile is its own file, not a `[profiles.x]` table.

**Gemini CLI, Cursor, Copilot CLI, Aider, Cline, Roo, Amp, Kiro.** Nothing documented for in-session subagents with per-call model selection. Run the inline fallback and record `inline, single model` in `Read by:`.
