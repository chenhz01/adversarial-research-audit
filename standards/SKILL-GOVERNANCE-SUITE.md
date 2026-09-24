# Skill Governance Suite — Overview

> `skill-spec` (archived) originally fronted the suite; **current front door: this repo (skill-audit-kit)** of the Skill Governance Suite:
> the producer-side quality system for AI agent skill libraries. Companion repositories:

| Repo | Role | Feeds into |
|---|---|---|
| **skill-spec** (archived, spec text preserved) | Skill format spec + `SPEC_TEMPLATE.md` + conformance examples | Suite schema baseline |
| skill-audit-kit (archived) | Structural audit CLI (field completeness, orphan refs, poisoning signals) | Governance chapter: audit |
| skill-scorecard (archived) | Quality scoring (version/trigger/usage metadata) | Governance chapter: scoring |
| skill-os (archived) | Lifecycle governance (ratchet rules, touch-while-fixing) | Governance chapter: lifecycle |
| agent-skill-doctor (archived) | Drift & health diagnostics | Governance chapter: health |
| skill-drift-doctor (archived) | Drift-specific scanner | Governance chapter: health |

## Relationship to ADAS (delivery-side standard)

The suite governs **producers** (skill libraries). The delivery-side acceptance contract is a
separate standard: [ADAS v0.9 draft](https://github.com/chenhz01/adversarial-research-audit/blob/main/standards/ADAS-v0.9-draft.md)
in [adversarial-research-audit](https://github.com/chenhz01/adversarial-research-audit).

- Skill Governance Suite → *how to build skill libraries that deserve trust* (producer)
- ADAS → *how to prove an agent's delivery is actually done* (receiver)

A "Governance & ADAS" companion chapter is planned once ADAS v1.0 freezes after first
external review.

## Status (honest ladder)

- L0 internal use: **achieved** (production: 516-skill library governed by these rules since 2026-09)
- L1 public spec: **in progress** (this repo + suite cross-links; RFC for comments open)
- L2 external adoption: not claimed (pending first external maintainer response)
- L3 third-party implementation: not claimed
