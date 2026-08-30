---
name: repo-disclosure
description: Decide whether a repository may be disclosed to an AI provider that can retain or train on what it receives.
disable-model-invocation: true
license: MIT
metadata:
  version: "1.2.0"
  repo-disclosure.audience: developers
  repo-disclosure.purpose: ai-data-safety
---

# Repo disclosure

Decide whether the target AI provider may receive information from this project. This is a **disclosure** decision, not a secret scan. The question is:

> If this provider may retain, reuse, or train on what it receives, what project information could leave the owner's control, and is that acceptable?

Report every finding by type, location, risk, and required action. Secret and personal values stay out of the report.

## Assessment target

Establish before deciding:

- the provider being assessed, and whether submitted data may be retained, reused, or used for training
- the intended use: static repository access, agentic/tool execution, or both
- the scope: repository, worktree, or directory
- the assessing agent: run the assessment with a provider already approved for the repository; the provider under evaluation must never be the one reading the files

Terms differ across tiers and endpoints of the same provider (consumer vs API vs enterprise, free vs paid, opt-out settings, zero-data-retention agreements); assess the exact tier and account in use, not the provider's headline policy. Unknown terms are assessed as retention-and-training, with that assumption stated.

Done when target, access mode, scope, and the separation of assessing agent from assessed provider are each known or explicitly assumed.

## Data classes

Classify each finding with the most restrictive class that applies: `RESTRICTED` > `CONFIDENTIAL` > `PRIVATE-OWNED` > `PUBLIC`.

- **PUBLIC**. Intentionally public: published open-source code, public documentation, synthetic examples, placeholder configuration. Compatible with a training-eligible provider on its own; local files, uncommitted changes, credentials, and connected tools can still make the working project unsafe.
- **PRIVATE-OWNED**. Non-public, wholly owned by the user, free of employer, client, collaborator, privacy, contractual, or licensing restriction (an unpublished personal project). Safe once the owner has authority to consent and accepts the provider's terms.
- **CONFIDENTIAL**. Non-public information whose disclosure would breach an employment, client, NDA, contractual, licensing, or security expectation: private company or client source; internal architecture, hostnames, infrastructure; non-public product plans, research, pricing, strategy; proprietary algorithms, business logic, datasets; security findings, incidents, operational procedures; internal tickets, meeting notes, support conversations; third-party licensed material not permitted for this use. Disclosable only with evidence that this provider/use is permitted. A file needs no `CONFIDENTIAL` label, and no credentials inside it, to be confidential.
- **RESTRICTED**. Exposure creates a direct security, privacy, regulatory, or account-access risk: passwords, API keys, tokens, session cookies, private keys, signing certificates, credential stores, production connection strings and configuration; cloud and package-registry credentials, Terraform state, Kubernetes configuration; real personal data (customer, candidate/student, employee, support, authentication, payment, regulated records) wherever it sits (dumps, exports, fixtures, logs, screenshots); live secrets present only in Git history. A confirmed restricted finding is **DO NOT USE** until it is outside the provider's reach. A possibly exposed credential gets a rotation or revocation recommendation; deletion alone leaves it live.

## Verdicts

Return exactly one overall verdict: the first rule that matches. One serious finding decides it; there is no score.

1. Restricted material is in reach → **DO NOT USE**.
2. Confidential material is in reach and this provider/use is known to be prohibited or unpermitted → **DO NOT USE**.
3. Non-public material is in reach and its ownership, policy, NDA, client, licensing, or disclosure authority is unresolved → **REQUIRES POLICY/OWNER APPROVAL** (blocking until resolved).
4. Unsafe material exists but an enforceable boundary keeps it out of reach → **SAFE WITH EXCLUSIONS**.
5. Everything in reach is public, private-owned with the owner's explicit consent to the provider's terms, or confidential with evidenced permission for this provider/use → **SAFE**.

Static and agentic use get separate verdicts; the overall verdict covers the requested use. When the requested use is unclear, report both and take the more restrictive.

## Reach

_Reach_ is everything the provider can receive during the intended workflow, not only tracked source:

- tracked source and documentation
- untracked, ignored, hidden, generated, and local developer configuration files, and symlink targets
- infrastructure definitions, deployment manifests, and database migrations
- diffs, patches, and Git history
- fixtures, exports, dumps, logs, screenshots
- terminal, test, build, and debug output
- environment variables and runtime configuration
- issues, tickets, PRs, and internal documentation
- anything behind connected tools: authenticated systems, cloud tooling, databases, email, calendars, support systems

Dependency caches and generic build output are out of reach unless they hold project-specific or real data. A Git-ignored file is as reachable as a tracked one; a clean working tree proves nothing.

## Process

### 1. Establish ownership and permission

Determine whether the project is public, personal, employer-owned, client-owned, educational, open-source, or mixed; who owns the source, data, documentation, and generated artifacts; whether the user has authority to consent to this provider's terms; and whether employer policy, client terms, NDAs, contracts, licences, or data-handling rules restrict disclosure.

Done when ownership and disclosure authority are each established or explicitly marked unresolved.

### 2. Inventory reach

Walk the repository and list every surface in the Reach section above for the requested access mode.

Done when every practical route by which the provider could receive project information is listed.

### 3. Check restricted data

Hunt the inventory for RESTRICTED material. Distinguish genuine secrets from placeholders, and real records from synthetic fixtures.

Done when every suspected restricted finding is confirmed, false positive, or unresolved. Unresolved suspected restricted material in reach counts as confirmed.

### 4. Review semantic confidentiality

Read ordinary-looking source and documentation for CONFIDENTIAL information a pattern scan misses. When uncertain:

> Would the owner reasonably object if this exact material were submitted to a provider allowed to retain or train on it?

Done when every item in the inventory has a data class and a disclosure decision.

### 5. Review Git history

When history is in reach, check for deleted secrets, removed production values, old client data, internal documents, and sensitive commit messages.

Done when the report states whether history was in scope and whether it changes the verdict.

### 6. Review agentic exposure

Assess tool execution separately from static access. Every surface in the Reach section is live here, plus what execution itself creates: tests or commands run against staging or production, verbose logging that prints sensitive data, and screenshots, exports, or logs generated during the run. A repository can be safe for static review and unsafe for agentic execution.

Done when static and agentic risk are separately stated, even when they share a verdict.

### 7. Test exclusions

**SAFE WITH EXCLUSIONS** needs an _enforceable_ boundary: one that removes access by construction. In order of preference:

1. a sanitized copy of the project
2. a separate worktree containing only approved material
3. a container or sandbox without restricted files, credentials, or live-system access
4. tool permissions that block every practical route to the excluded data

Path-based read rules are weak wherever unrestricted shell, connected tools, symlinks, environment variables, or runtime systems reach the same data; manual discipline is no boundary at all.

Done when every exclusion names its boundary and no alternate route around it is apparent.

### 8. Decide

Apply the verdict rules to the evidence, checking both dimensions: **technical leakage** (secrets, personal data, real datasets, logs, history, tool output) and **governance** (ownership, client/employer obligations, licensing, disclosure authority, provider terms). An unresolved dimension yields the blocking verdict for that issue with lowered confidence, never **SAFE**.

Done when the overall, static, and agentic verdicts are consistent with the findings and the requested use.

## Report format

```markdown
# AI repo data-safety assessment

**Overall verdict:** SAFE | SAFE WITH EXCLUSIONS | DO NOT USE | REQUIRES POLICY/OWNER APPROVAL
**Static repository:** <verdict>
**Agentic/tool execution:** <verdict>
**Assessed for:** <provider, or the conservative training-eligible assumption>
**Assessed scope:** <repo/worktree/directory and access mode>
**Confidence:** High | Medium | Low

## Why
<the decisive reasons, one short paragraph>

## Blocking findings
<per blocker: severity, data class, location, type of information, why it matters, required action, or `None found`>

## Confidentiality findings
<per area: data class, path or project area, why it may be sensitive, whether the assessed provider/use may receive it>

## Unknowns
<unresolved ownership, policy, licensing, provider-term, or scope questions that affect the verdict, or `None`>

## Safe scope
<parts of the project usable with the assessed provider, or `Entire assessed scope`>

## Excluded scope
<each item that must stay out of reach, with the boundary enforcing it, or `None`>

## Recommendation
<one direct operational recommendation>
```

Recommendation examples:

- Do not use a training-eligible model for this repository.
- Use the training-eligible model only with a sanitized copy containing the approved public source.
- The repository is technically clean; owner/employer approval for provider training is required before proceeding.
- Static source review is acceptable; use an approved private model for tests and tools that can access live systems.
