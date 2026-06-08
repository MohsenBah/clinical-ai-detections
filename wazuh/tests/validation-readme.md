# Detection Validation Framework 

Automated regression tests for Wazuh rules **100100–100401**.

## Files

| File | Purpose |
|---|---|
| `validation-cases.json` | Test cases with `expect_rules` / `reject_rules` |
| `prompt-injection-log-samples.json` | Raw sample logs (reference / manual logtest) |
| `wazuh-logtest-notes.md` | Manual logtest guide |
| `../../scripts/validate_rules.py` | Offline + Wazuh validation runner |
| `../../scripts/run_validation.sh` | Convenience wrapper |

## Quick run

```bash
# CI / local — no Wazuh required
python3 scripts/validate_rules.py --offline

# On Wazuh manager host
sudo scripts/run_validation.sh --wazuh
# or
python3 scripts/validate_rules.py --wazuh
```

## Case format

Single event:

```json
{
  "id": "blocked-instruction-override",
  "event": { "event_type": "query", "decision": "blocked", ... },
  "expect_rules": ["100100", "100102"],
  "reject_rules": ["100300"]
}
```

Correlation sequence (rule **100200**):

```json
{
  "id": "repeated-probing-correlation",
  "events": [ ...3 blocked events, same user_id... ],
  "expect_rules_per_event": [
    ["100100", "100102"],
    ["100100"],
    ["100100", "100102", "100200"]
  ]
}
```

## CI

GitHub Actions workflow `.github/workflows/validate-detections.yml` runs offline validation on every push/PR to `main`.

## Offline vs Wazuh

| Mode | When to use |
|---|---|
| `--offline` | CI, dev laptops without Wazuh; mirrors rule XML logic |
| `--wazuh` | Pre-deploy check on manager with rules installed |

Offline mode does not replace Wazuh logtest for decoder/parent-rule chain validation — run `--wazuh` before production rule deploys.
