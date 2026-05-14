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

## Validation Command

On a Wazuh manager:

```bash
/var/ossec/bin/wazuh-logtest
```

Paste one JSON event at a time.

## Notes

This first version validates single-event detections only.

Correlation detections such as repeated probing will be added later.
