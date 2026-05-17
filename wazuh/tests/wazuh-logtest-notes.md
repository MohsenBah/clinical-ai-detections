# Wazuh Logtest Notes

## Purpose

Use this document to validate that sample Clinical AI Gateway audit logs trigger the expected Wazuh rules.

## Files

Sample logs:

```text
wazuh/tests/prompt-injection-log-samples.json
```

Decoder:

```text
wazuh/decoders/ai-gateway-json.xml
```

Rules:

```text
wazuh/rules/100100-prompt-injection.xml
```

## Expected Results

### Instruction Override Event

Expected rule:

```text
100100
100102
```

### System Prompt Extraction Event

Expected rule:

```text
100100
100101
```

### Allowed Query Event

Expected result:

```text
No prompt injection alert
```

### Repeated Probing (3+ blocked events)

Expected rule:

```text
100100
100200
```

### PHI Probing

Expected rule:

```text
100300
```

### Abnormal Query Length (>2000 chars)

Expected rule:

```text
100400
100401 (if blocked)
```

## Validation Command

On a Wazuh manager:

```bash
/var/ossec/bin/wazuh-logtest
```

Paste one JSON event at a time.

## Notes

Updated to include correlation rules (repeated probing) and keyword-based detections (PHI probing, abnormal length).
Test with the expanded sample set in prompt-injection-log-samples.json.

**New test cases added:**
- Multiple blocked events from same user (triggers 100200)
- PHI-related queries (triggers 100300)
- Very long queries (triggers 100400/100401)
