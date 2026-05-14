# Data Sources

## Purpose

This document defines the log sources used by the Clinical AI Detections repository.

The first detection source is the structured audit log emitted by the Clinical AI Gateway.

## Primary Source: Clinical AI Gateway Audit Logs

The gateway emits JSON logs for each query attempt.

These logs are used to detect:

- Prompt injection attempts
- Blocked requests
- Abuse patterns
- Potential probing activity
- Suspicious usage patterns

## Example Event

```json
{
  "timestamp": "2026-05-09T18:24:10.442Z",
  "event_type": "query",
  "request_id": "def-456",
  "user_id": "demo-user",
  "session_id": "demo-session",
  "decision": "blocked",
  "reason": "blocked_pattern:ignore all previous instructions",
  "query_length": 74,
  "latency_ms": 2.1
}
```

## Important Fields

| Field | Description | Detection Use |
|---|---|---|
| timestamp | Event time | Timeline analysis |
| event_type | Type of event | Filter query events |
| request_id | Unique request identifier | Investigation correlation |
| user_id | User identifier | User-based behavior analysis |
| session_id | Session identifier | Session-based behavior analysis |
| decision | allowed or blocked | Security decision |
| reason | Allow/block reason | Attack category |
| query_length | Query size | Exfiltration or abuse signal |
| response_length | Response size | Output anomaly signal |
| latency_ms | Request latency | Performance and anomaly signal |

## Logging Constraints

The gateway should not log:

- Raw PHI
- Full clinical records
- Credentials
- Secrets
- Raw model responses

Detection content should be built around metadata, decisions, and normalized reasons.

## Future Data Sources

Planned future sources:

- Ollama logs
- Reverse proxy logs
- Wazuh agent events
- Suricata alerts
- System file integrity monitoring
- Authentication logs
