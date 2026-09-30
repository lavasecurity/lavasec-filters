import {createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';

export const CONTEXT = Buffer.from('Lava catalog definitions v1\n');
export const MAX_BYTES = 8 * 1024 * 1024;
export const MAX_VALIDITY = 31 * 86400;
export const DEFINITION_FIELDS = ['id', 'name', 'category', 'risk_level',
  'license_name', 'attribution', 'project_url', 'source_url', 'redistribution_mode',
  'parse_format', 'license_text_url', 'notice_url'];
const OPTIONAL = new Set(['license_text_url', 'notice_url']);
const FORMATS = new Set(['auto', 'plain_domains', 'hosts', 'adblock', 'dnsmasq']);
function requireThat(condition, message) { if (!condition) throw new Error(message); }
function validID(id) { return typeof id === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(id) && id !== '.' && id !== '..'; }
function url(value, httpsOnly = false) {
  requireThat(typeof value === 'string' && value.length <= 8192, 'Invalid URL');
  const parsed = new URL(value);
  requireThat((httpsOnly ? parsed.protocol === 'https:' : ['http:', 'https:'].includes(parsed.protocol)) &&
    parsed.hostname && !parsed.username && !parsed.password && !parsed.hash, 'Invalid URL');
  // Connection-time DNS/IP and redirect safety remain the clients' existing responsibility.
  return value;
}
export function definitions(entries, guardrail = false) {
  requireThat(Array.isArray(entries) && entries.length <= 512, 'Invalid inventory');
  return entries.map(entry => {
    const definition = {};
    for (const field of DEFINITION_FIELDS) {
      const value = entry[field] ?? (OPTIONAL.has(field) ? null : undefined);
      if (!OPTIONAL.has(field) || value !== null)
        requireThat(typeof value === 'string' && value.length <= 8192, `Invalid definition field: ${field}`);
      definition[field] = value;
    }
    requireThat(validID(definition.id), 'Invalid source ID');
    requireThat(FORMATS.has(definition.parse_format), 'Invalid parser');
    requireThat(!guardrail || definition.category === 'guardrail', 'Invalid guardrail tier');
    requireThat(guardrail || definition.category !== 'guardrail', 'Invalid community tier');
    url(definition.source_url, true);
    url(definition.project_url);
    for (const field of OPTIONAL) if (definition[field] !== null) url(definition[field]);
    return definition;
  }).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}
export function inventory(value) {
  const sources = definitions(value.sources);
  const guardrails = definitions(value.guardrails, true);
  requireThat(sources.length + guardrails.length <= 512, 'Inventory too large');
  const ids = new Set();
  for (const source of [...sources, ...guardrails]) {
    const id = source.id.toLowerCase();
    requireThat(!ids.has(id), 'Duplicate source ID'); ids.add(id);
  }
  requireThat(Array.isArray(value.withdrawn_sources) && value.withdrawn_sources.length <= 4096, 'Invalid withdrawals');
  const withdrawn_sources = [...value.withdrawn_sources].sort();
  for (const id of withdrawn_sources) {
    requireThat(validID(id) && !ids.has(id.toLowerCase()), 'Conflicting withdrawal');
    ids.add(id.toLowerCase());
  }
  requireThat(Number.isSafeInteger(value.revision) && value.revision > 0, 'Invalid revision');
  return {revision: value.revision, sources, guardrails, withdrawn_sources};
}
function message(payload) { return Buffer.concat([CONTEXT, payload]); }
function base64(value, max) {
  requireThat(typeof value === 'string' && value.length <= Math.ceil(max / 3) * 4, 'Invalid base64 length');
  const bytes = Buffer.from(value, 'base64');
  requireThat(bytes.length <= max && bytes.toString('base64') === value, 'Invalid base64');
  return bytes;
}
function rawPublicKey(value) {
  const bytes = base64(value, 32);
  requireThat(bytes.length === 32, 'Invalid public key');
  return createPublicKey({key: {kty: 'OKP', crv: 'Ed25519', x: bytes.toString('base64url')}, format: 'jwk'});
}
export function readAuthorization(envelope, pins, now, checkTime = true) {
  requireThat(envelope && envelope.format === 1 && validID(envelope.key_id), 'Unsupported authorization');
  requireThat(Object.hasOwn(pins, envelope.key_id), 'Unpinned signing key');
  const payload = base64(envelope.payload, 1024 * 1024);
  const signature = base64(envelope.signature, 64);
  requireThat(signature.length === 64 && verify(null, message(payload), rawPublicKey(pins[envelope.key_id]), signature), 'Invalid signature');
  const manifest = JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(payload));
  requireThat(manifest.format === 1 && manifest.purpose === 'lava-catalog-definitions' && manifest.key_id === envelope.key_id, 'Wrong authorization purpose');
  requireThat(Number.isSafeInteger(manifest.issued_at) && Number.isSafeInteger(manifest.expires_at) &&
    manifest.issued_at >= 0 && manifest.expires_at > manifest.issued_at &&
    manifest.expires_at - manifest.issued_at <= MAX_VALIDITY, 'Invalid validity interval');
  if (checkTime) requireThat(now >= manifest.issued_at && now < manifest.expires_at, 'Authorization not current');
  return {...inventory(manifest), issued_at: manifest.issued_at, expires_at: manifest.expires_at};
}
function sameInventory(a, b) {
  return isDeepStrictEqual(inventory(a), inventory(b));
}
export function verifyCatalog(catalog, pins, {now = Math.floor(Date.now() / 1000), previous, retiredKeys = {}} = {}) {
  requireThat(Buffer.byteLength(JSON.stringify(catalog)) <= MAX_BYTES && catalog.schema_version === 2, 'Invalid catalog');
  const manifest = readAuthorization(catalog.catalog_authorization, pins, now);
  const actual = {...catalog, revision: manifest.revision, withdrawn_sources: catalog.withdrawn_sources ?? []};
  requireThat(sameInventory(actual, manifest), 'Catalog definitions differ from authorization');
  if (previous) {
    const prior = readAuthorization(previous, {...retiredKeys, ...pins}, now, false);
    requireThat(manifest.revision >= prior.revision, 'Catalog rollback');
    if (manifest.revision === prior.revision) {
      requireThat(sameInventory(manifest, prior), 'Conflicting inventory revision');
      requireThat(manifest.issued_at >= prior.issued_at && manifest.expires_at >= prior.expires_at, 'Authorization renewal rollback');
    }
    // Withdrawals are cumulative: an older retired ID cannot silently reappear later.
    requireThat(prior.withdrawn_sources.every(id => manifest.withdrawn_sources.includes(id)), 'Lost withdrawal');
    const active = new Set([...manifest.sources, ...manifest.guardrails].map(source => source.id));
    requireThat([...prior.sources, ...prior.guardrails].every(source => active.has(source.id) ||
      manifest.withdrawn_sources.includes(source.id)), 'Removed source lacks withdrawal');
  }
  return manifest;
}
export function signCatalog(candidate, approved, privateKeyPEM, keyID,
  {now = Math.floor(Date.now() / 1000), validity = 7 * 86400, previous, pins, retiredKeys = {}} = {}) {
  requireThat(candidate.schema_version === 2 && validID(keyID), 'Invalid catalog/key');
  requireThat([...candidate.sources, ...candidate.guardrails].every(source => source.default_enabled === false),
    'Legacy selection flags must remain neutral');
  const policy = inventory(approved);
  requireThat(sameInventory({...candidate, revision: policy.revision,
    withdrawn_sources: candidate.withdrawn_sources ?? policy.withdrawn_sources}, policy), 'Candidate differs from approved inventory');
  const manifest = {format: 1, purpose: 'lava-catalog-definitions', key_id: keyID,
    ...policy, issued_at: now, expires_at: now + validity};
  const payload = Buffer.from(JSON.stringify(manifest));
  const privateKey = createPrivateKey(privateKeyPEM);
  requireThat(privateKey.asymmetricKeyType === 'ed25519', 'Signing requires Ed25519');
  const envelope = {format: 1, key_id: keyID, payload: payload.toString('base64'),
    signature: sign(null, message(payload), privateKey).toString('base64')};
  const result = {...candidate, withdrawn_sources: policy.withdrawn_sources, catalog_authorization: envelope};
  const publicKey = createPublicKey(privateKey).export({format: 'jwk'});
  const ownPins = {[keyID]: Buffer.from(publicKey.x, 'base64url').toString('base64')};
  verifyCatalog(result, pins ?? ownPins, {now, previous, retiredKeys});
  return result;
}
