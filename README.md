# Lava filters

`catalog/inventory.json` is the **only authoring source** for Lava's filter catalog:
source URLs, membership, defaults, parsers, attribution, categories and withdrawals.
Provider list contents remain at their original URLs. User-added custom lists are not
part of this catalog and need no Lava signature.

Edit the inventory through a reviewed pull request. Increment `revision` whenever a
signed definition or withdrawal changes; put every removed ID in `withdrawn_sources`.
Never reuse retired IDs. Ordinary provider content updates need no catalog edit or approval.

## Generated consumers

Run `npm run generate` and `npm test` (Node 22+). `dist/blocklist-catalog.json` is the
schema-1 compatibility projection consumed by app code generators and the docs site.
Their vendored files are pinned generated snapshots, not independently editable catalogs.
Use `src/sync-filter-catalog.mjs TARGET --ref COMMIT_SHA` to adopt a reviewed revision,
then run the consumer's generator. `--check` checks the snapshot against its pinned commit.

The delivery service reads this repository's main-branch inventory to collect provider
observations and assemble candidates. Database source rows are generated operational
copies; database edits cannot author membership or URLs. The signing job builds definitions
from its own checked-out inventory and copies only observations whose ID, URL and parser
match. Missing observations do not remove a source. Only the signed artifact is delivered.

## Signature boundary

Ed25519 signs `Lava catalog definitions v1\n` followed by the exact payload bytes.
Schema-2 documents retain their existing fields and add `catalog_authorization` and
`withdrawn_sources`. Old readers ignore these additions. The payload covers definitions,
membership, withdrawals, revision and validity. Hashes/counts/provider versions remain
advisory; ordinary provider updates are not content approval. Existing strict guardrail
hash checks are not strengthened by this definition-only signature. No guardrails are
currently included. Custom lists remain outside this signing requirement.

Consumers pin public keys and use signed revision/expiry for authenticity and freshness.
The default validity is seven days, with a maximum of 31. Renewals of an unchanged revision
are automatic. Fresh/reset installations can accept an older still-valid signature until
expiry; offline clients cannot learn withdrawals immediately. This is catalog admission,
not immediate remote revocation of prepared filtering artifacts.

## Public repository, protected signing

Catalog definitions, public keys, source code and signatures are public. Private signing
keys stay in the protected `catalog-signing` environment. Signing runs only on protected
`main`; public pull requests run secret-free tests on GitHub-hosted ephemeral runners.
Delivery credentials cannot write this repository or change signing keys/workflows.
Changes to the inventory, signing code, workflows and ownership rules require trusted review.

Signing and delivery remain disabled until real public pins, signing credentials and
repository/environment protections are commissioned. The test fixture key is never a
production key. Review full history, PRs and artifacts before a public visibility change.
The imported inventory preserves the public API catalog captured on 2026-09-30 (33 sources,
no guardrails), preserving existing app onboarding presets. StevenBlack remains in the Balanced preset;
this resolves the old API metadata discrepancy without changing saved user selections. The docs repository is archived and its old YAML is historical. This supersedes operational
source-table authoring paths; historical migrations are not ongoing catalog definitions.

For local signing: `node src/cli.mjs sign candidate.json catalog/inventory.json KEY_ID
policy/public-keys.json previous.json signed.json`, with `LAVA_CATALOG_PRIVATE_KEY_FILE`
pointing to a protected PEM. Use `-` as previous only for deliberate first publication.
Retired public pins can verify checkpoints but cannot authorize incoming catalogs.
