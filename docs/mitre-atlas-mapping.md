# MITRE ATLAS Mapping

This document maps Clinical AI Gateway Wazuh detection rules to [MITRE ATLAS](https://atlas.mitre.org/) adversarial ML techniques and tactics.

## Framework Reference

| ID | Name | Type |
|---|---|---|
| AML.TA0001 | Reconnaissance | Tactic |
| AML.TA0002 | ML Model Access | Tactic |
| AML.T0051 | LLM Prompt Injection | Technique |
| AML.T0057 | LLM Data Leakage | Technique |

### Technique Summaries

**AML.T0051 — LLM Prompt Injection**  
Adversaries craft malicious prompts that cause an LLM to ignore its original instructions and follow attacker-controlled behavior. In clinical deployments this includes jailbreaks, instruction overrides, and system prompt extraction attempts. Maps to OWASP LLM01.

**AML.T0057 — LLM Data Leakage**  
Adversaries craft prompts that induce the model to leak sensitive information from training data, connected sources, or prior context. In healthcare contexts this includes PHI probing for SSNs, addresses, and medical record identifiers.

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

100400  Abnormal query length
└── 100401  Blocked long query
```

---

## OWASP LLM Top 10 Cross-Reference

| OWASP Risk | ATLAS Technique | Relevant Rules |
|---|---|---|
| LLM01 Prompt Injection | AML.T0051 | 100100, 100101, 100102, 100200, 100400, 100401 |
| LLM06 Excessive Agency | AML.T0051 | 100200 (automated repeated probing) |
| LLM07 System Prompt Leakage | AML.T0051 | 100101 |
| Sensitive data exposure | AML.T0057 | 100300 |

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

## Planned Extensions

| Scenario | Proposed ATLAS Mapping | Status |
|---|---|---|
| RAG data poisoning | AML.T0058 (LLM Prompt Injection — Indirect) | Telemetry available; rule TBD |
| Off-hours access | AML.TA0001 | Rule 100500 planned |
| Model tampering | AML.T0010 / AML.T0044 | Rule 100600 planned |

---

*Last updated: Phase 3.2A — all 7 active rules mapped.*
