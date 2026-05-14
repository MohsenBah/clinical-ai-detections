# Detection Roadmap

## Objective

Build detection content for clinical LLM systems using structured security logs.

The first goal is not to detect every possible LLM attack. The first goal is to create a clear, testable detection pipeline from gateway event to SIEM alert.

## Stage 1: Prompt Injection Detection

Detect when the Clinical AI Gateway blocks known prompt injection patterns.

Detection inputs:

- `event_type=query`
- `decision=blocked`
- `reason=blocked_pattern:*`

Expected output:

- Wazuh alert with high severity
- Rule ID in the 100100 range
- Clear alert description

## Stage 2: Repeated Probing

Detect repeated blocked attempts from the same user or session.

Possible signals:

- Multiple blocked events from the same user
- Multiple blocked events from the same session
- Many different blocked reasons in a short period

## Stage 3: PHI Probing

Detect suspicious behavior related to clinical data extraction.

Possible signals:

- Repeated PHI filter triggers
- Queries targeting identifiers
- Queries asking for demographics, address, insurance, or contact details
- Unusual query repetition

## Stage 4: Abnormal Usage

Detect anomalous gateway behavior.

Possible signals:

- Very long prompts
- Unusually frequent requests
- Off-hours access
- High failure rate
- High blocked-to-allowed ratio

## Stage 5: Model and Infrastructure Signals

Detect possible model tampering or abnormal backend behavior.

Possible signals:

- Model file modification
- Unexpected model reloads
- Ollama errors
- Unexpected outbound access from AI services

## Guiding Principle

Every detection should have:

- A clear data source
- A reproducible sample event
- A Wazuh rule or detection query
- A validation method
- A documented limitation
