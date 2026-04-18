---
name: "soc-response-planner"
description: "Performs state-driven multi-candidate lookahead planning and ranking. Invoke when selecting the best incident response action under time/risk constraints."
---

# SOC Response Planner

## Purpose
Select the best response action via multi-candidate simulation, rollout-based estimation, and explicit scoring.

## Invoke When
- You already have incident + state + RAG output.
- Multiple valid response actions exist and one must be prioritized.
- You need reduced hallucination by rejecting non-improving actions.

## Inputs
- Current 6D state
- Candidate actions (3~5 preferred)
- History actions
- Planner config (`rollout_count`, `depth`, penalty weights)

## Output Contract
Return JSON only:

```json
{
  "recommended_action": {},
  "ranked_actions": [],
  "reasons": {},
  "expected_recovery_effect": {},
  "risk_alerts": [],
  "executable": {
    "shell": "",
    "api": ""
  },
  "explainability": {}
}
```

## Scoring Policy
- Must use:
  `Score = state_gain - time_penalty - risk_penalty`
- Hallucination rule:
  If action improves no state dimension, mark invalid (`hallucination=true`).
- Recovery time:
  Sum serial costs; for same parallel group, use max cost.

## Decision Rules
- Prefer actions that improve weakest state dimensions first.
- Break ties by lower risk, then lower recovery time.
- Ensure recommendation remains operationally executable.

## Quality Checklist
- Every ranked action includes reason and expected effect.
- At least one explicit risk warning for high-risk actions.
- Output preserves machine-readable structure for automation.
