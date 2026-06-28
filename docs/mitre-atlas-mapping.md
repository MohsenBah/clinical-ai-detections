# MITRE ATLAS Mapping

This document maps Clinical AI Gateway Wazuh detection rules to [MITRE ATLAS](https://atlas.mitre.org/) adversarial ML techniques and tactics.

## Framework Reference

| ID | Name | Type |
|---|---|---|
| AML.TA0000 | ML Supply Chain Compromise | Tactic |
| AML.TA0001 | Reconnaissance | Tactic |
| AML.TA0002 | ML Model Access | Tactic |
| AML.T0051 | LLM Prompt Injection | Technique |
| AML.T0057 | LLM Data Leakage | Technique |
| AML.T0058 | RAG Poisoning / Indirect Prompt Injection | Technique |

### Technique Summaries

**AML.T0051 — LLM Prompt Injection**  
Adversaries craft malicious prompts that cause an LLM to ignore its original instructions and follow attacker-controlled behavior. In clinical deployments this includes jailbreaks, instruction overrides, and system prompt extraction attempts. Maps to OWASP LLM01.

**AML.T0057 — LLM Data Leakage**  
Adversaries craft prompts that induce the model to leak sensitive information from training data, connected sources, or prior context. In healthcare contexts this includes PHI probing for SSNs, addresses, and medical record identifiers, as well as administrative requests for credentials, API keys, and system configuration.

**AML.T0058 — RAG Poisoning / Indirect Prompt Injection**  
Adversaries tamper with the documents or data ingested into a Retrieval-Augmented Generation pipeline so that retrieved context manipulates model behavior. Repeated malformed or failed ingestion attempts can indicate probing of the ingest endpoint. Maps to OWASP LLM04.

### Tactic Summaries

**AML.TA0001 — Reconnaissance**  
Adversaries gather information about the AI system to plan later operations. PHI probing queries fall here when attackers enumerate what sensitive data the model will surface.

**AML.TA0002 — ML Model Access**  
Adversaries interact with the model inference interface to manipulate behavior, bypass controls, or establish a foothold for further attacks. Prompt injection and input-stuffing attempts map here.

---

## Rule-to-ATLAS Mapping

| Rule ID | Detection | Level | Technique | Tactic | Gateway Signal |
|---|---|---|---|---|---|
| 100100 | Prompt injection blocked | 8 | AML.T0051 | AML.TA0002 | `decision=blocked`, `reason=blocked_pattern:*` |
| 100101 | System prompt extraction | 10 | AML.T0051 | AML.TA0002 | Child of 100100, `reason` contains `system prompt` |
| 100102 | Instruction override | 9 | AML.T0051 | AML.TA0002 | Child of 100100, `ignore all previous instructions` |
| 100200 | Repeated probing | 10 | AML.T0051 | AML.TA0002 | 3+ Rule 100100 events per `user_id` in 5 min |
| 100300 | PHI probing | 9 | AML.T0057 | AML.TA0001 | Query matches PHI keyword patterns |
| 100310 | Admin / credential exfiltration | 10 | AML.T0057 | AML.TA0001 | `decision=blocked`, `reason=blocked_admin_scope:*` |
| 100320 | RAG ingestion failure | 6 | AML.T0058 | AML.TA0000 | `event_type=ingestion`, `status=failed` |
| 100321 | Repeated ingestion failures | 10 | AML.T0058 | AML.TA0000 | 3+ Rule 100320 events per `collection_name` in 10 min |
| 100400 | Abnormal query length | 7 | AML.T0051 | AML.TA0002 | `query_length_bucket=large` |
| 100401 | Blocked long query | 8 | AML.T0051 | AML.TA0002 | Child of 100400, `decision=blocked` |

---

## Rule Hierarchy

```
100100  Prompt injection (base)
├── 100101  System prompt extraction
└── 100102  Instruction override

100200  Repeated probing (correlation on 100100)

100300  PHI probing (standalone)

100310  Admin / credential exfiltration (standalone)

100320  RAG ingestion failure
└── 100321  Repeated ingestion failures (correlation on 100320)

100400  Abnormal query length
└── 100401  Blocked long query
```

---

## OWASP LLM Top 10 Cross-Reference

| OWASP Risk | ATLAS Technique | Relevant Rules |
|---|---|---|
| LLM01 Prompt Injection | AML.T0051 | 100100, 100101, 100102, 100200, 100400, 100401 |
| LLM02 Sensitive Disclosure | AML.T0057 | 100300, 100310 |
| LLM04 Data and Model Poisoning | AML.T0058 | 100320, 100321 |
| LLM06 Excessive Agency | AML.T0051 / AML.T0057 | 100200 (automated probing), 100310 (admin/credential exfiltration) |
| LLM07 System Prompt Leakage | AML.T0051 | 100101 |
| Sensitive data exposure | AML.T0057 | 100300, 100310 |

Full HIPAA, OWASP, and NIST mappings: [compliance-matrix.md](compliance-matrix.md)

---

## Wazuh Rule Annotation Format

Wazuh `<mitre>` blocks support **only** `<id>` — not `<tactic>`. Tactic mappings (AML.TA0001, AML.TA0002) are documented in this file and in `coverage-matrix.md` for compliance reporting; they are not embedded in rule XML.

```xml
<mitre>
  <id>AML.T0051</id>
</mitre>
```

Using `<tactic>` causes `wazuh-logtest` to fail with `Invalid option 'tactic' for rule`.

Install rules from `wazuh/rules/100100-prompt-injection.xml` and verify with samples in `wazuh/tests/prompt-injection-log-samples.json`.

---

## Additional Scenarios

| Scenario | Proposed ATLAS Mapping | Status |
|---|---|---|
| Content-level RAG poisoning | AML.T0058 (RAG Poisoning / Indirect Injection) | Failed-ingest detection deployed (100320/100321); content provenance pending |
| Off-hours access | AML.TA0001 | Not deployed (100500) |
| Model tampering | AML.T0010 / AML.T0044 | Not deployed (100600) |

---

*All 10 active rules mapped (100100–100102, 100200, 100300, 100310, 100320, 100321, 100400, 100401).*
