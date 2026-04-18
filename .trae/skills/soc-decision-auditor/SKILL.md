---
name: "soc-decision-auditor"
description: "Audits response decisions for evidence traceability, policy safety, and command validity. Invoke before final execution or when reviewing plan quality."
---

# SOC Decision Auditor

## Purpose
Run a pre-execution audit on response plans to ensure safety, traceability, and explainability.

## Invoke When
- A final action recommendation is ready for operator approval.
- You need a gate to catch risky or weakly grounded decisions.
- Post-incident review requires decision accountability.

## Inputs
- Final response plan JSON
- Incident baseline + RAG summary
- Optional policy constraints (business hours, critical systems, change windows)

## Output Contract
Return JSON only:

```json
{
  "audit_result": "pass|warning|fail",
  "findings": [
    {
      "severity": "high|medium|low",
      "category": "evidence|risk|execution|policy|explainability",
      "detail": "string",
      "fix_suggestion": "string"
    }
  ],
  "execution_guardrails": [],
  "final_note": "string"
}
```

## Audit Checks
- Evidence traceability: every action maps to log/IOC/RAG evidence.
- Risk sanity: high-impact actions have rollback/containment notes.
- Execution validity: shell/API commands are syntactically plausible.
- Policy compliance: avoid prohibited operations in sensitive windows.
- Explainability completeness: recommendation and ranking rationale exist.

## Fail Conditions
- Missing evidence for recommended action.
- Non-executable command or malformed API action.
- High-risk action with no mitigation note.

## Quality Checklist
- Findings sorted by severity.
- Each finding contains concrete fix suggestion.
- Output remains parseable JSON for CI/CD gating.
