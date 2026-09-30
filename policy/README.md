# Commissioning the independent inventory

Signing is disabled until `approved-inventory.json` and `public-keys.json` are reviewed
and committed here. No production inventory or key is inferred from a live API export.

The inventory has `revision` (positive safe integer), complete `sources` and `guardrails`
definition arrays, and cumulative `withdrawn_sources`. See the fixture for field names.
Changing definitions or withdrawals increments revision. Routine validity renewal does not.
`public-keys.json` maps approved key IDs to raw 32-byte Ed25519 public keys in base64.
Fixture keys must never appear in this file or app release pins.

Protect this repository's default branch, signing workflow and `catalog-signing` environment.
Only trusted branch code runs with the private key. Infra credentials cannot write here or
change environment secrets. Required reviewers/environment protection depend on the GitHub
plan: verify actual settings, not merely the workflow's environment name, before activation.
