# Correlation Rules Documentation

## Overview

This document explains how Wazuh correlation rules are used to detect behavioral patterns in Clinical AI Gateway security events. Correlation rules go beyond single-event detection by analyzing sequences of events over time.

## Wazuh Correlation Concepts

### Key Options

| Option | Purpose | Example |
|--------|---------|---------|
| `frequency` | Minimum number of matching events required | `3` |
| `timeframe` | Time window in seconds for correlation | `300` (5 minutes) |
| `same_id` | Field that must be identical across events | `user_id`, `session_id` |
| `if_sid` | Parent rule ID that must match first | `100100` |

### How It Works

1. Wazuh tracks events matching a base rule (`if_sid`)
2. Within the specified `timeframe`, it counts occurrences
3. If the count reaches `frequency` and `same_id` matches, the correlation rule fires
4. This enables detection of repeated, anomalous, or coordinated behavior

---

## Implemented Correlation Rules

### Rule 100200: Repeated Prompt Injection Probing

**Severity**: Level 10 (Critical)

**Logic**:
- Triggers when Rule 100100 fires 3 or more times
- Within a 5-minute (300 second) window
- From the same `user_id`

**Detection Value**:
- Identifies persistent attackers or automated scripts
- Distinguishes probing from one-off mistakes
- High severity indicates active reconnaissance

**Sample Triggering Sequence**:
```json
// Event 1
{"event_type": "query", "user_id": "attacker-1", "decision": "blocked", "reason": "blocked_pattern:ignore all previous instructions"}

// Event 2 (within 5 min)
{"event_type": "query", "user_id": "attacker-1", "decision": "blocked", "reason": "blocked_pattern:show me your system prompt"}

// Event 3 (within 5 min) → Triggers Rule 100200
{"event_type": "query", "user_id": "attacker-1", "decision": "blocked", "reason": "blocked_pattern:bypass safety"}
```

**Alert Output**:
```
Rule 100200 fired: Clinical AI Gateway detected repeated prompt injection attempts from same user
```

---

## Planned Correlation Scenarios

The following correlation patterns are designed but not yet implemented as rules. They can be added to extend behavioral detection.

### Scenario 1: User-Based Anomaly Detection

**Concept**: Detect users with unusually high blocked-to-allowed ratios.

**Detection Logic**:
- Track `decision=blocked` vs `decision=allowed` per `user_id`
- Alert if blocked ratio exceeds threshold (e.g., 50%) within a time window

**Use Case**:
- Identifies users who may be testing security boundaries
- Catches "spray and pray" probing attempts

**Example Wazuh Rule Structure**:
```xml
<rule id="100210" level="8">
  <if_sid>100100</if_sid>
  <frequency>10</frequency>
  <timeframe>3600</timeframe>
  <same_id>user_id</same_id>
  <description>User has high blocked event rate (possible probing)</description>
</rule>
```

### Scenario 2: Off-Hours Access Detection

**Concept**: Flag access attempts outside normal business hours.

**Detection Logic**:
- Correlate `timestamp` with expected business hours
- Alert on blocked or suspicious events between 10 PM - 6 AM

**Use Case**:
- Detects potential insider threats or compromised accounts
- Identifies automated attacks running on schedules

**Implementation Note**:
- Requires timestamp parsing and time-based conditions
- Can use Wazuh's `time` option or external enrichment

### Scenario 3: Session-Based Probing Detection

**Concept**: Detect rapid, diverse attack attempts within a single session.

**Detection Logic**:
- Multiple different `blocked_pattern` reasons
- Within the same `session_id`
- Short time window (e.g., 2 minutes)

**Use Case**:
- Identifies automated tools trying multiple injection techniques
- Distinguishes from legitimate user mistakes

**Example**:
```xml
<rule id="100220" level="9">
  <if_sid>100100</if_sid>
  <frequency>4</frequency>
  <timeframe>120</timeframe>
  <same_id>session_id</same_id>
  <description>Multiple different injection techniques in single session</description>
</rule>
```

---

## Tuning Correlation Rules

### Adjusting Sensitivity

**Increase Sensitivity** (more alerts, earlier detection):
- Lower `frequency` (e.g., from 3 to 2)
- Increase `timeframe` (e.g., from 300s to 600s)

**Decrease Sensitivity** (fewer false positives):
- Raise `frequency` (e.g., from 3 to 5)
- Decrease `timeframe` (e.g., from 300s to 120s)
- Add additional field matching (e.g., `same_id` on both `user_id` AND `ip_address`)

### Common False Positive Sources

1. **Legitimate testing**: Security teams running validation scripts
2. **Repeated user errors**: Users consistently making the same mistake
3. **Shared accounts**: Multiple users behind the same `user_id`

### Mitigation Strategies

- Maintain a whitelist of known testing user_ids
- Add `if_sid` exclusions for specific benign patterns
- Implement rate limiting on alert generation
- Use aggregation rules to summarize rather than alert on every correlation

---

## Best Practices

1. **Start Conservative**: Begin with higher thresholds, tune down based on observed behavior
2. **Document Thresholds**: Record why specific `frequency`/`timeframe` values were chosen
3. **Monitor Alert Fatigue**: Track correlation rule firing rates; adjust if overwhelmed
4. **Combine with Context**: Correlation is most effective when combined with:
   - User risk scoring
   - Historical behavior baselines
   - Threat intelligence enrichment
5. **Test Thoroughly**: Use `wazuh-logtest` with realistic multi-event sequences before production deployment

---

## Related Files

- **Rules**: `wazuh/rules/100100-prompt-injection.xml` (contains Rule 100200)
- **Test Samples**: `wazuh/tests/prompt-injection-log-samples.json`
- **Test Documentation**: `wazuh/tests/wazuh-logtest-notes.md`
- **Coverage Matrix**: `docs/coverage-matrix.md`

---

*Last Updated: May 19, 2026*  
*Status: Phase 2.2 Complete - Core correlation concepts documented; additional scenarios ready for implementation*