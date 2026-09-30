# Lava catalog authorization

Independent approval of Lava's catalog definitions. This repository does not approve
individual domain additions, mirror provider lists, or restrict user-added custom URLs.
The phone continues downloading ordinary list updates directly from approved providers.

`src/authorization.mjs` signs Ed25519 authorizations against a complete separately reviewed
inventory. A publisher cannot obtain a signature for a substituted, missing or extra source.
`src/cli.mjs` signs/verifies local artifacts; `src/publish-job.mjs` supplies the protected
GitHub job. The signing job outputs an artifact; a separate infra publishing arm uploads it
through its signed-publication endpoint. No Cloudflare/Supabase signing key is introduced.

## Verification

Node 22 or newer, no dependencies: `npm test`.

`fixtures/catalog-v1.json` is a cross-language fixture with a disposable public test key.
Its private key was discarded. It is not a production catalog or trusted source inventory.

## Protocol v1

Schema-2 catalog JSON keeps its original fields and adds `catalog_authorization` and
`withdrawn_sources`. Old clients ignore additions. The authorization contains `format: 1`,
`key_id`, base64 `payload`, and base64 `signature`. The signature message is the UTF-8 bytes
`Lava catalog definitions v1\n` followed by the exact decoded payload bytes.

Payload: `format: 1`, `purpose: "lava-catalog-definitions"`, matching `key_id`, positive integer
`revision`, integer Unix seconds `issued_at` and exclusive `expires_at`, complete `sources`
and `guardrails`, and cumulative `withdrawn_sources`. Maximum validity is 31 days; the job
renews for seven days. A newer revision authorizes definition changes; same-revision renewals
must preserve definitions/withdrawals. Clients retain a rollback checkpoint; clearing app
storage resets local history, and offline phones cannot learn withdrawals immediately.
Every source or guardrail removed from the previous inventory must be explicitly withdrawn;
once withdrawn, that ID cannot be reused by a later revision.

Definition fields are the closed `DEFINITION_FIELDS` list in source: IDs, labels, URLs,
category/tier, default enablement, parser, redistribution and legal metadata. Hashes, counts,
source version and provider publication timestamps are advisory observations and deliberately
excluded. Catalog version/generated-at are delivery/cache metadata, not authenticity or
freshness evidence. Use the signed revision and expiry for those decisions. Existing strict
client guardrail hash behavior is not strengthened into signed content approval by this work.

## Local usage

```
node src/cli.mjs verify catalog.json policy/public-keys.json previous.json
LAVA_CATALOG_PRIVATE_KEY_FILE=/secure/key.pem node src/cli.mjs sign candidate.json policy/approved-inventory.json key-id policy/public-keys.json previous.json signed.json
```

Use `-` in place of `previous.json` only for the deliberate first publication. Signing does
not publish. Store only public keys in Git. Never use untrusted PR code with the signing key.
During rotation, `LAVA_CATALOG_RETIRED_KEYS_FILE` can point to checkpoint-only public pins;
these verify the previous authorization but cannot authorize an incoming catalog.

## Rollout

1. Review the independent inventory and production public key in `policy/`; configure actual
   branch/environment permissions. See `policy/README.md`. These files are intentionally absent.
2. Deploy infra candidate/signed-publication support. The candidate token has read-only scope;
   the publishing token has only signed-publication scope. Neither can change this inventory.
3. Enable the protected signing job after configuring pins, endpoint URLs and environment
   secrets. Bootstrap once explicitly, then disable bootstrap and require the prior signature.
4. Deliver the first generated artifact to infra and check old-app decoding. Enable
   `CATALOG_DELIVERY_ENABLED` with a `CATALOG_DISPATCH_TOKEN` scoped to Actions write on
   **infra only** for automatic artifact handoff. The signing arm can dispatch the publisher
   but does not hold its Cloudflare publication credential. The publisher downloads artifacts
   with a separate read-only credential; it cannot modify this repository or invoke signing.
5. Ship iOS pins and strict enforcement after signed delivery is established. Unsigned cached
   catalogs are not promoted to authenticated state. Key rotation/retirement needs coordinated
   app pins and checkpoints; an incoming catalog cannot introduce its own public key.

No signing secrets, trusted production inventory, deployment or strict client activation are
included in this implementation. The infra plan is
https://github.com/lavasecurity/lavasec-infra/pull/312 .
