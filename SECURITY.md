# Security Notes

ATT&CKLens is for defensive education with synthetic or authorised lab data only.

## Safety Boundaries

- Do not use real organisational logs, secrets, credentials, or regulated data.
- Do not use the tool to plan intrusions, bypass controls, evade monitoring, or perform unauthorised testing.
- Treat every input as untrusted text. The application rejects prompt-injection attempts that ask for hidden prompts or internal instructions.
- When evidence is ambiguous, the tool returns no mapping instead of guessing.

## Defensive Output Policy

The app may suggest detection, triage, remediation, and analyst follow-up questions. It must not provide exploit instructions or operational attack steps.

## Data Handling

The MVP runs locally and does not persist, transmit, or upload submitted evidence. Users remain responsible for ensuring they only paste authorised synthetic or lab data.

## Known Limitations

The mapping logic is intentionally narrow and deterministic for the benchmark. Analysts should verify all outputs against trusted telemetry, local context, and current ATT&CK documentation before acting.
