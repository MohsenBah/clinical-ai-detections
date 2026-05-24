# Clinical AI Detections - Update Recommendations

**Date**: May 24, 2026  
**Status**: Phase 3 - Advanced Detection & Integration (In Progress)

## Executive Summary

The clinical-ai-detections repository has completed Phase 1 and Phase 2 foundation work. We are now entering **Phase 3: Advanced Detection & Integration** to achieve production-ready clinical LLM security monitoring.

**Phase 1 & 2 Status**: ✅ Complete

---

## Current State Assessment

### ✅ Completed Work

**Phase 1: Foundation Improvements**
- ✅ Wazuh decoder updated to native JSON parsing
- ✅ 5 detection rules implemented (100100-100401)
- ✅ Coverage matrix and test documentation updated

**Phase 2: Behavioral Detection & Visualization**
- ✅ 2 Grafana dashboards created (Security Overview, Prompt Injection)
- ✅ Correlation rules documentation (Rule 100200, 100300, 100400)
- ✅ 21 test samples with PHI probing, rate limiting, normal queries
- ✅ Complete README with pipeline documentation and screenshots

### Current Gaps (Phase 3 Focus)

1. **Gateway Integration**: Missing `event_type=ingestion`, `query_category`, model metrics
2. **Compliance Mapping**: No MITRE ATLAS or regulatory framework mapping
3. **Infrastructure**: No unified deployment automation
4. **Validation Framework**: No automated testing harness

---

## Phase 3: Advanced Detection & Integration (Current Focus)

### 3.1 Gateway Enhancements (coordinated with clinical-ai-gateway)

**Priority**: High  
**Status**: In Progress

#### Tasks:

**A. Add `event_type=ingestion` for RAG Pipeline Monitoring**
- Implement audit logging in `data_ingestion.py`
- Log events when clinical data is ingested into vector database
- Capture: `event_type`, `records_ingested`, `data_path`, `user_id`, `timestamp`
- Enable detection of RAG data poisoning attempts

**B. Add `query_category` Classification**
- Classify queries into categories:
  - `medical` - Clinical/medical questions
  - `administrative` - System/admin queries
  - `adversarial` - Security testing/probing
- Implement lightweight classification in gateway
- Log `query_category` in all audit events
- Enable behavioral analysis by query type

**C. Implement Model Performance Metrics Logging**
- Capture LLM response metrics:
  - `model_name`, `tokens_generated`, `generation_time_ms`
  - `prompt_tokens`, `completion_tokens`
- Log model errors and fallback events
- Enable performance anomaly detection

**Files to Modify**:
- `clinical-ai-gateway/gateway/services/data_ingestion.py`
- `clinical-ai-gateway/gateway/routes/query.py`
- `clinical-ai-gateway/gateway/routes/data.py`
- `clinical-ai-gateway/gateway/middleware/audit.py`

---

### 3.2 MITRE ATLAS & Compliance Mapping

**Priority**: High  
**Status**: Pending

#### Tasks:

**A. Map All 5 Existing Rules to MITRE ATLAS Techniques**

| Rule ID | Rule Name | MITRE ATLAS Technique | Technique ID |
|---------|-----------|----------------------|--------------|
| 100100 | Prompt injection blocked | Prompt Injection | AML.T0051 |
| 100101 | System prompt extraction | Prompt Injection | AML.T0051 |
| 100102 | Instruction override | Prompt Injection | AML.T0051 |
| 100200 | Repeated probing | Prompt Injection (Automated) | AML.T0051 |
| 100300 | PHI probing | Model Extraction / Data Exfiltration | AML.T0057 |
| 100400 | Abnormal query length | Prompt Injection / Evasion | AML.T0051 |

**B. Create Compliance Matrix Document**

Create `docs/compliance-matrix.md` mapping detections to:

- **HIPAA §164.312** - Technical Safeguards
  - Access Control (164.312(a))
  - Audit Controls (164.312(b))
  - Integrity (164.312(c))
  - Transmission Security (164.312(e))

- **OWASP LLM Top 10 (2025)**
  - LLM01: Prompt Injection
  - LLM02: Insecure Output Handling
  - LLM06: Excessive Agency
  - LLM07: System Prompt Leakage

- **NIST AI RMF 1.0**
  - Govern
  - Map
  - Measure
  - Manage

**C. Add Compliance Annotations to Rules**

Update `wazuh/rules/100100-prompt-injection.xml` with:
```xml
<compliance>
  <hipaa>164.312(b)</hipaa>
  <owasp>LLM01</owasp>
  <nist>Measure</nist>
  <mitre>AML.T0051</mitre>
</compliance>
```

---

### 3.3 Infrastructure as Code

**Priority**: Medium  
**Status**: Pending

#### Tasks:

**A. Create Unified `docker-compose.yml`**

Create `infrastructure/docker-compose.yml` with services:
```yaml
services:
  gateway:
    build: ../../clinical-ai-gateway
    ports: ["8000:8000"]
    volumes:
      - ./logs:/app/logs

  wazuh-manager:
    image: wazuh/wazuh-manager:latest
    ports:
      - "1514:1514"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
    volumes:
      - wazuh_api:/var/ossec/api
      - wazuh_queue:/var/ossec/queue
      - wazuh_var:/var/ossec/var
      - wazuh_logs:/var/ossec/logs

  wazuh-indexer:
    image: wazuh/wazuh-indexer:latest
    ports: ["9200:9200"]

  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:latest
    ports: ["5601:5601"]
    depends_on:
      - wazuh-indexer

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    volumes:
      - grafana_data:/var/lib/grafana
      - ../../clinical-ai-detections/grafana/dashboards:/etc/grafana/provisioning/dashboards

  ollama:
    image: ollama/ollama:latest
    volumes:
      - ollama_data:/root/.ollama

  chroma:
    image: chromadb/chroma:latest
    ports: ["8001:8000"]
    volumes:
      - chroma_data:/chroma/chroma
```

**B. Add Ansible Playbooks for Rule Deployment**

Create `infrastructure/ansible/`:
```
ansible/
├── playbooks/
│   ├── deploy-wazuh.yml
│   ├── deploy-rules.yml
│   └── deploy-dashboards.yml
├── roles/
│   ├── wazuh-manager/
│   │   ├── tasks/
│   │   ├── templates/
│   │   └── vars/
│   └── wazuh-agent/
├── inventory/
│   └── hosts.yml
└── ansible.cfg
```

**Example `deploy-rules.yml`**:
```yaml
---
- name: Deploy Clinical AI Detection Rules
  hosts: wazuh_managers
  tasks:
    - name: Copy decoder
      copy:
        src: "{{ playbook_dir }}/../../wazuh/decoders/ai-gateway-json.xml"
        dest: /var/ossec/etc/decoders/

    - name: Copy rules
      copy:
        src: "{{ playbook_dir }}/../../wazuh/rules/100100-prompt-injection.xml"
        dest: /var/ossec/etc/rules/

    - name: Restart Wazuh manager
      systemd:
        name: wazuh-manager
        state: restarted
```

**C. Document Deployment Architecture**

Create `docs/deployment-architecture.md`:
- Network topology diagram
- Component interaction flow
- Port mappings and firewall rules
- Data flow from gateway to SIEM
- Scaling considerations
- Backup and recovery procedures

---

### 3.4 Detection Validation Framework (Future)

**Status**: Planned (After 3.1-3.3)

- Automated test harness using `wazuh-logtest`
- False positive rate tracking
- Detection efficacy metrics dashboard
- Regular rule tuning documentation

---

## Implementation Priority (Updated)

| Phase | Timeline | Status |
|-------|----------|--------|
| Phase 1 | May 17-18 | ✅ Complete |
| Phase 2 | May 19-22 | ✅ Complete |
| **Phase 3.1** | May 24-26 | 🔄 **In Progress** |
| **Phase 3.2** | May 27-29 | ⏳ Pending |
| **Phase 3.3** | May 30 - Jun 2 | ⏳ Pending |
| Phase 3.4 | June 3-5 | ⏳ Future |

---

## Success Metrics (Updated)

### Current Achievement

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Detection coverage | 8+ scenarios | 6 scenarios | 🟡 75% |
| Test coverage | 25+ samples | 21 samples | 🟡 84% |
| Dashboards | 3 production-ready | 2 created | 🟡 67% |
| Rules with MITRE | 10+ rules | 0 mapped | ⭕ 0% |
| Documentation | Complete | 90% | 🟢 Near Complete |

### Phase 3 Targets

- ✅ All 5 rules mapped to MITRE ATLAS
- ✅ Compliance matrix (HIPAA, OWASP, NIST)
- ✅ Unified deployment with Wazuh + Grafana + Gateway
- ✅ `event_type=ingestion` implemented
- ✅ `query_category` classification working
- ✅ Model performance metrics logged

---

## Related Updates Needed in clinical-ai-gateway

### Completed ✅
1. ~~Add `blocked_category` field to audit logs~~
2. ~~Add `ingestion` event type for data pipeline monitoring~~ *(In Progress - 3.1A)*
3. ~~Add rate limit violation details~~
4. ~~Include `query_category` classification~~ *(In Progress - 3.1B)*

### New Requirements (Phase 3.1)
5. Add model performance metrics (`tokens_generated`, `generation_time_ms`)
6. Log RAG ingestion events with record counts
7. Classify queries into medical/administrative/adversarial categories

---

## Next Actions

**Immediate (This Week)**:
1. Begin 3.1A: Add `event_type=ingestion` to data ingestion service
2. Begin 3.1B: Implement `query_category` classification logic
3. Begin 3.2A: Map existing 5 rules to MITRE ATLAS techniques

**This Sprint**:
4. Complete 3.1 Gateway Enhancements
5. Create compliance matrix document
6. Start unified docker-compose.yml

---

*This document is the living roadmap for clinical AI detection engineering.*  
*Updated: May 24, 2026 - Transitioning to Phase 3*