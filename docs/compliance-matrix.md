# Compliance Matrix

Maps Clinical AI Gateway controls and Wazuh detection rules to regulatory and industry frameworks.

This is a **lab/reference mapping** for portfolio and audit discussions — not legal compliance certification.

Related docs: [mitre-atlas-mapping.md](mitre-atlas-mapping.md) · [coverage-matrix.md](coverage-matrix.md)

---

## Rule-Level Compliance Summary

| Rule ID | Detection | HIPAA §164.312 | OWASP LLM | NIST AI RMF |
|---|---|---|---|---|
| 100100 | Prompt injection blocked | (a), (b) | LLM01 | Measure, Manage |
| 100101 | System prompt extraction | (b) | LLM01, LLM07 | Measure, Manage |
| 100102 | Instruction override | (b) | LLM01 | Measure, Manage |
| 100200 | Repeated probing | (a), (b) | LLM01, LLM06 | Measure, Manage |
| 100300 | PHI probing | (b), (c) | LLM02, LLM06 | Measure, Map |
| 100400 | Abnormal query length | (b) | LLM01, LLM04 | Measure |
| 100401 | Blocked long query | (b) | LLM01, LLM04 | Measure, Manage |

---

## HIPAA Security Rule — §164.312 Technical Safeguards

| Safeguard | Requirement (summary) | Gateway control | Detection / observability |
|---|---|---|---|
| **164.312(a)** Access control | Unique user identification; access to ePHI limited to authorized persons | `user_id`, `session_id` on all audit events; rate limiting | **100200** (repeated blocks per `user_id`); future off-hours rule |
| **164.312(b)** Audit controls | Record and examine access and activity in systems containing ePHI | Structured JSON audit log (`security.log`); query + ingestion events | All rules; Grafana dashboards; Promtail → Loki |
| **164.312(c)** Integrity | Protect ePHI from improper alteration or destruction | Presidio at ingest; output filter (placeholder); ingest audit trail | Ingestion events (`event_type=ingestion`); **100300** PHI probing; future RAG poisoning rules |
| **164.312(d)** Person or entity authentication | Verify persons/entities seeking access | Not implemented in lab gateway | Planned (API auth, mTLS) |
| **164.312(e)** Transmission security | Guard against unauthorized access to ePHI in transit | TLS at reverse proxy / infra layer | N/A at application rule layer |

### HIPAA mapping notes

- Lab uses **synthetic data only** — mappings demonstrate control design, not production HIPAA compliance.
- **164.312(b)** is the strongest fit: every gateway decision is logged and detections consume those logs.
- **164.312(c)** is partially addressed via ingestion monitoring and PHI probing detection, not full integrity attestation.

---

## OWASP LLM Top 10 (2025)

| Risk | Name | Gateway mitigation | Wazuh detection | Status |
|---|---|---|---|---|
| **LLM01** | Prompt Injection | Input validation, block patterns | 100100, 100101, 100102, 100200, 100400, 100401 | ✅ |
| **LLM02** | Sensitive Information Disclosure | Presidio redaction, output filter | 100300 (PHI keyword probing) | ✅ Detect / partial prevent |
| **LLM03** | Supply Chain | Dependency pinning, container images | — | ⏳ Process, not rule |
| **LLM04** | Data and Model Poisoning | Controlled ingest path, audit events | Ingestion telemetry; Grafana RAG dashboard; rule TBD | 🔄 Telemetry only |
| **LLM05** | Improper Output Handling | `filter_output()` middleware | `output_modified` in audit logs | 🔄 Partial |
| **LLM06** | Excessive Agency | Gateway-only tool access; no autonomous actions | 100200 (automated probing pattern) | ✅ Detect |
| **LLM07** | System Prompt Leakage | Block extraction patterns | 100101 | ✅ |
| **LLM08** | Vector and Embedding Weaknesses | Record-ID de-identification in RAG | — | 🔄 Gateway design |
| **LLM09** | Misinformation | Clinical disclaimers in system prompt | — | ⏳ Model/policy |
| **LLM10** | Unbounded Consumption | Rate limiting per `user_id` | Rate-limit audit events; 100400 long queries | ✅ Partial |

---

## NIST AI RMF 1.0

| Function | Category | How this project applies |
|---|---|---|
| **Govern** | Policies, roles, oversight | MedSecLab architecture docs; synthetic-data-only policy; repo boundaries |
| **Map** | Context, risks, impacts | Threat scenarios in coverage matrix; MITRE ATLAS mapping; PHI probing context |
| **Measure** | Assess, track, evaluate | Wazuh rules, Grafana metrics, audit telemetry, logtest validation |
| **Manage** | Prioritize, respond, recover | Block decisions at gateway; SIEM alerts; demo runbooks (`clinical-ai-gateway/demo/`) |

### NIST ↔ detection mapping

| NIST function | Artifacts | Rules / signals |
|---|---|---|
| Govern | `MedSecLab/README.md`, gateway security controls | Policy-level |
| Map | `coverage-matrix.md`, `mitre-atlas-mapping.md` | 100300 (recon / PHI) |
| Measure | Wazuh rules, Grafana dashboards, `security.log` | 100100–100401 |
| Manage | Gateway block + alert response | 100100, 100200, 100401 |

---

## Gateway Controls (Non-Wazuh)

These support compliance narratives but are not Wazuh rules:

| Control | Location | Frameworks |
|---|---|---|
| Structured audit logging | `gateway/middleware/audit.py` | HIPAA 164.312(b), NIST Measure |
| Rate limiting | `gateway/middleware/rate_limit.py` | OWASP LLM10, HIPAA 164.312(a) |
| Input validation | `gateway/middleware/input_validation.py` | OWASP LLM01 |
| Output filtering | `gateway/middleware/output_filter.py` | OWASP LLM02, LLM05 |
| RAG ingest audit events | `gateway/routes/data.py` | HIPAA 164.312(c), OWASP LLM04 |
| Query / ingestion telemetry | `gateway/routes/query.py` | NIST Measure |

---

## Wazuh Rule Annotations

Wazuh does **not** support custom `<compliance>` XML elements (same limitation as `<tactic>` in `<mitre>`). Compliance mappings are documented here and in XML comments above each rule in `wazuh/rules/100100-prompt-injection.xml`.

Example comment format:

```xml
<!-- compliance: hipaa=164.312(a),(b); owasp=LLM01,LLM06; nist=Measure,Manage -->
```

---

## Gaps and Planned Work

| Gap | Framework | Planned action |
|---|---|---|
| RAG poisoning detection rule | OWASP LLM04, HIPAA 164.312(c) | Wazuh rules on ingestion anomalies |
| Off-hours access | HIPAA 164.312(a) | Rule 100500 |
| Authentication / mTLS | HIPAA 164.312(d),(e) | Gateway hardening phase |
| Full output PHI filtering | OWASP LLM02 | Presidio on model output |
| Compliance certification | All | Out of scope for homelab |

---

*Phase 3.3 — compliance matrix for clinical AI detection engineering.*
