# Detection Coverage Matrix

This matrix tracks detection coverage for clinical AI security scenarios.

| Scenario | Data Source | Detection Status | Rule ID | MITRE ATLAS | Notes |
|---|---|---|---|---|---|
| Direct prompt injection | Gateway audit logs | Covered | 100100 | AML.T0051 / AML.TA0002 | Detects blocked prompt injection patterns |
| System prompt extraction | Gateway audit logs | Covered | 100101 | AML.T0051 / AML.TA0002 | Child rule when `reason` matches system prompt |
| Instruction override | Gateway audit logs | Covered | 100102 | AML.T0051 / AML.TA0002 | Child rule for instruction override pattern |
| Safety bypass request | Gateway audit logs | Partial | 100100 | AML.T0051 / AML.TA0002 | Covered when reason starts with `blocked_pattern` |
| Repeated probing | Gateway audit logs | Covered | 100200 | AML.T0051 / AML.TA0002 | Correlation: 3+ blocked events per user in 5 min |
| PHI probing | Gateway audit logs | Covered | 100300 | AML.T0057 / AML.TA0001 | PHI keyword detection with 5+ test samples |
| Abnormal query length | Gateway audit logs | Covered | 100400 | AML.T0051 / AML.TA0002 | Long query detection via `query_length_bucket` |
| Blocked long query | Gateway audit logs | Covered | 100401 | AML.T0051 / AML.TA0002 | Child rule when long query is blocked |
| Off-hours access | Gateway audit logs | Planned | 100500 | AML.TA0001 | Requires user/time context |
| Model tampering | Host/Wazuh FIM | Planned | 100600 | TBD | Requires file integrity monitoring |
| RAG data poisoning | App/data logs | Research | TBD | AML.T0058 (planned) | Ingestion telemetry available; detection rule pending |

## Coverage Legend

| Status | Meaning |
|---|---|
| Covered | Detection rule exists and has sample logs |
| Partial | Some cases covered, but not complete |
| Planned | Detection design exists but not implemented |
| Research | Needs more investigation |

## MITRE ATLAS Summary

| Technique | Tactic | Rules |
|---|---|---|
| AML.T0051 — LLM Prompt Injection | AML.TA0002 — ML Model Access | 100100, 100101, 100102, 100200, 100400, 100401 |
| AML.T0057 — LLM Data Leakage | AML.TA0001 — Reconnaissance | 100300 |

Full mapping details: [mitre-atlas-mapping.md](mitre-atlas-mapping.md) · [compliance-matrix.md](compliance-matrix.md)

## Compliance Summary

| Framework | Primary rules | Doc |
|---|---|---|
| HIPAA §164.312(b) Audit controls | All rules + gateway audit log | [compliance-matrix.md](compliance-matrix.md) |
| OWASP LLM01 Prompt injection | 100100–100102, 100200, 100400, 100401 | [compliance-matrix.md](compliance-matrix.md) |
| OWASP LLM02 Sensitive disclosure | 100300 | [compliance-matrix.md](compliance-matrix.md) |
| NIST AI RMF Measure | 100100–100401, Grafana telemetry | [compliance-matrix.md](compliance-matrix.md) |

## Test Coverage Summary

- **Total test samples**: 21
- **Prompt injection patterns**: 7 samples
- **PHI probing queries**: 5 samples (triggers Rule 100300)
- **Rate limiting events**: 3 samples
- **Normal clinical queries**: 3 samples (false positive testing)
- **Abnormal length queries**: 2 samples (triggers Rule 100400/100401)
- **Repeated probing sequences**: 3+ samples from same user (triggers Rule 100200)
