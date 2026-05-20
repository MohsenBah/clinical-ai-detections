# Detection Coverage Matrix

This matrix tracks detection coverage for clinical AI security scenarios.

| Scenario | Data Source | Detection Status | Rule ID | Notes |
|---|---|---|---|---|
| Direct prompt injection | Gateway audit logs | Covered | 100100 | Detects blocked prompt injection patterns |
| System prompt extraction | Gateway audit logs | Partial | 100100 | Covered when gateway blocks known patterns |
| Safety bypass request | Gateway audit logs | Partial | 100100 | Covered when reason starts with blocked_pattern |
| Repeated probing | Gateway audit logs | **In Progress** | 100200 | Correlation rule added for repeated blocked events |
| PHI probing | Gateway audit logs | **Covered** | 100300 | PHI keyword detection with 5+ test samples |
| Abnormal query length | Gateway audit logs | **In Progress** | 100400, 100401 | Rules for long queries and blocked long queries added |
| Off-hours access | Gateway audit logs | Planned | 100500 | Requires user/time context |
| Model tampering | Host/Wazuh FIM | Planned | 100600 | Requires file integrity monitoring |
| RAG data poisoning | App/data logs | Research | TBD | Requires ingestion pipeline events |

## Coverage Legend

| Status | Meaning |
|---|---|
| Covered | Detection rule exists and has sample logs |
| Partial | Some cases covered, but not complete |
| Planned | Detection design exists but not implemented |
| Research | Needs more investigation |

## Test Coverage Summary

- **Total test samples**: 21
- **Prompt injection patterns**: 7 samples
- **PHI probing queries**: 5 samples (triggers Rule 100300)
- **Rate limiting events**: 3 samples
- **Normal clinical queries**: 3 samples (false positive testing)
- **Abnormal length queries**: 2 samples (triggers Rule 100400/100401)
- **Repeated probing sequences**: 3+ samples from same user (triggers Rule 100200)