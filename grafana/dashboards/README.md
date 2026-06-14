# Grafana Dashboards

This directory contains dashboard JSON exports for clinical AI security monitoring.

## Available Dashboards

### 1. Clinical AI Security Overview
**File**: `clinical-ai-security-overview.json`

**Purpose**: High-level view of all gateway activity and Phase 3.1A telemetry.

**Security panels**:
- Total queries per hour
- Blocked vs allowed ratio
- Blocked queries over time
- Top blocked reasons
- Top users by blocked events
- Raw gateway logs

**Telemetry panels** (Phase 3.1B):
- Avg generation time, tokens/sec, total tokens (stat)
- Query latency percentiles P50/P95/P99 (timeseries)
- Token usage over time — prompt vs completion tokens (timeseries)
- Query category distribution (pie chart)
- Latency by query category (bar chart)

### 2. Prompt Injection Attempts
**File**: `prompt-injection-dashboard.json`

**Purpose**: Detailed analysis of prompt injection attacks.

**Panels**:
- Prompt injection blocks and instruction override counts
- Injection attempts over time
- Blocked pattern distribution
- Top attacking users
- Raw injection events
- **Block decision latency** P50/P95 (Phase 3.1B)
- **Blocks by query category** (Phase 3.1B)

### 3. RAG Ingestion Monitoring
**File**: `rag-ingestion-dashboard.json`

**Purpose**: Monitor RAG data ingestion for poisoning and operational anomalies (Phase 3.1B).

**Panels**:
- Ingestion event count and records ingested (stat)
- Ingestion success rate (stat)
- Ingestion volume over time — records and chunks (timeseries)
- Ingestion latency percentiles P50/P95 (timeseries)
- Ingestion outcomes by status (pie chart)
- Top ingested sources by `source_type` and `data_path` (table)
- Raw ingestion events (logs)

## Usage

### Import to Grafana

```bash
# Via UI
# 1. Open Grafana
# 2. Go to Dashboards → Import
# 3. Upload JSON file or paste content

# Via API
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @clinical-ai-security-overview.json
```

### Data Source Requirements

These dashboards expect:
- **Data Source**: Loki
- **Query Language**: LogQL
- **Label**: `job="clinical-ai-gateway"`

**Query event fields** (`event_type=query`):
- `decision`, `reason`, `user_id`, `session_id`
- `query_category`, `blocked_category`, `matched_pattern`
- `latency_ms`, `generation_time_ms`
- `prompt_tokens`, `completion_tokens`, `total_tokens`
- `model_name`, `backend`

**Ingestion event fields** (`event_type=ingestion`):
- `source_type`, `record_count`, `chunk_count`, `status`
- `data_path`, `collection_name`, `duration_ms`, `error_message`

### Wazuh Integration

Ensure Wazuh logs are forwarded to your observability stack:
- Wazuh → Filebeat → Logstash → Elasticsearch/Loki
- Or use Wazuh's native integration with Grafana via Wazuh API

## Status

**Implemented**: 3 dashboards (Security Overview, Prompt Injection, RAG Ingestion)

---

*Dashboards are designed for Grafana 9.x+ / 13.x schema exports and Loki 2.x+.*
