---
name: "soc-incident-triage"
description: "Performs SOC incident triage and state initialization. Invoke when new security logs/alerts arrive and you need a structured incident object plus 6D state baseline."
---

# SOC Incident Triage

## Purpose
Turn raw IDS/EDR/Sysmon/traffic logs into a high-quality incident baseline for downstream planning.

## Invoke When
- User provides fresh security alerts or unstructured logs.
- The system needs initial `incident object` and first-pass 6D state.
- There is uncertainty about incident scope and affected assets.

## Inputs
- Raw logs (IDS/EDR/Sysmon/NetFlow)
- Alert metadata (severity, source, timestamp)
- Optional asset inventory snippets

## Output Contract
Return JSON only:

```json
{
  "incident": {
    "event_summary": "string",
    "ioc": {
      "ip": [],
      "domain": [],
      "cve": [],
      "process": []
    },
    "affected_assets": [],
    "raw_logs": [],
    "timestamp": "ISO-8601"
  },
  "state": {
    "containment": 0.0,
    "assessment": 0.0,
    "preservation": 0.0,
    "eviction": 0.0,
    "hardening": 0.0,
    "recovery": 0.0,
    "explanation": "evidence-based explanation"
  }
}
```

## Rules
- Do not invent IOC/CVE/assets not evidenced in input.
- Normalize duplicated indicators and keep canonical forms.
- Keep conservative scores when evidence is weak.
- Include short evidence rationale for each high-confidence finding.

## Quality Checklist
- Incident fields complete and parseable.
- At least one explicit correlation between log evidence and state score.
- Timestamp normalized to ISO-8601.
