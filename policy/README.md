# Signing policy

Catalog definitions live only in `../catalog/inventory.json`. Do not create a second
approved-inventory file here. `public-keys.json` maps approved key IDs to raw 32-byte
Ed25519 public keys in base64; it remains absent until production key commissioning.
`retired-keys.json` is optional and can verify prior checkpoints only.

Keep the private key in the protected `catalog-signing` environment. Protect main and
require trusted review of inventory, signing code and workflow changes. Public PR code
must never access signing secrets. The environment permits protected main only; production
publisher credentials have no write access here. Automatic renewals run reviewed main code
and do not require human approval of provider content updates.
