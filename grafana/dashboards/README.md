# Grafana Dashboards

This directory contains dashboard JSON exports for clinical AI security monitoring.

## Available Dashboards

### 1. Clinical AI Security Overview
**File**: `clinical-ai-security-overview.json`

**Purpose**: High-level view of all gateway activity
- Total queries per hour
- Blocked vs Allowed ratio (pie chart)
- Blocked queries over time (timeseries)
- Top blocked reasons (barchart)
- Top users by blocked events (table)

**Key Metrics**:
- Query volume trends
- Security posture (block rate)
- High-risk users

### 2. Prompt Injection Attempts
**File**: `prompt-injection-dashboard.json`

**Purpose**: Detailed analysis of prompt injection attacks
- Total injection attempts (with severity thresholds)
- Injection attempts by pattern (pie chart)
- Attempts over time (timeseries)
- Severity distribution (barchart)
- Top attackers by user_id/session_id (table)

**Key Metrics**:
- Attack pattern breakdown
- Attack velocity
- Attacker profiling

## Planned Dashboards

- User and Session Risk Scoring
- Gateway Performance and Latency
- PHI Probing Detection
- Repeated Probing Analysis

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
- **Data Source**: Loki (or Wazuh-indexed logs)
- **Query Language**: LogQL
- **Log Format**: JSON with fields:
  - `event_type`
  - `decision`
  - `reason`
  - `user_id`
  - `session_id`
  - `rule_id`
  - `level`

### Wazuh Integration

Ensure Wazuh logs are forwarded to your observability stack:
- Wazuh → Filebeat → Logstash → Elasticsearch/Loki
- Or use Wazuh's native integration with Grafana via Wazuh API

## Status

**Implemented**: 2 dashboards (Security Overview, Prompt Injection)  
**In Progress**: Phase 2 enhancements  
**Planned**: Risk scoring, performance, PHI probing dashboards

---

*Dashboards are designed for Grafana 9.x+ and Loki 2.x+.*