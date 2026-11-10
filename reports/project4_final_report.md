# SecureNova Project 4 - Before/After Security Comparison

Generated: 2026-11-10T12:32:58.641430+00:00

## Attack comparison

| Attack category | Project 3 vulnerable baseline | Project 4 guardrail result |
|---|---|---|
| Indirect Prompt Injection | ATTACK_SUCCEEDED | BLOCKED |
| Agent Identity Spoofing | ATTACK_SUCCEEDED | BLOCKED |
| System Prompt Extraction | ATTACK_SUCCEEDED | BLOCKED |
| Role Escalation | ATTACK_SUCCEEDED | BLOCKED |
| RAG Poisoning and MCP Abuse | ATTACK_SUCCEEDED | BLOCKED |

## Summary

- Project 3 vulnerable baseline: 5/5 categories successful.
- Project 4 local tests: 5/5 categories blocked.
- Local simulation success-rate reduction: **100%**.

## Additional Project 4 controls

- JWT redaction demonstrated: True
- Ed25519 key pair generated: True
- Valid signed message accepted: True
- Tampered message rejected: True
- Anomaly detection: 20+ requests in 60 seconds, scope change, and expired-token reuse test cases triggered alerts.
- Auth0 refresh-token replay: `invalid_grant` returned with HTTP 403.

## Limitations

- Project 3 and Project 4 tests are deterministic local simulations.
- Project 4 guardrail results do not establish production LLM protection.
- No live MCP tool or customer data was accessed.
- The 100 percent reduction is limited to these five tested local attack categories.
- Auth0 token rotation was tested separately; its replay response returned invalid_grant with HTTP 403.

## Evidence files

- `evidence/guardrail_results.json`
- `evidence/ed25519_results.json`
- `evidence/anomaly_detection_results.json`
- `comparison/before_after_comparison.json`
