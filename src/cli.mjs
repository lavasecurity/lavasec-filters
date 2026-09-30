import {readFileSync, writeFileSync} from 'node:fs';
import {signCatalog, verifyCatalog, MAX_BYTES} from './authorization.mjs';
function json(path) {
  const bytes = readFileSync(path);
  if (bytes.length > MAX_BYTES) throw new Error('Input exceeds catalog limit');
  return JSON.parse(bytes);
}
function previousAuthorization(path) {
  if (!path || path === '-') return undefined;
  const authorization = json(path).catalog_authorization;
  if (!authorization) throw new Error('Previous catalog has no authorization');
  return authorization;
}
try {
  const retiredKeys = process.env.LAVA_CATALOG_RETIRED_KEYS_FILE ? json(process.env.LAVA_CATALOG_RETIRED_KEYS_FILE) : {};
  const [command, ...args] = process.argv.slice(2);
  if (command === 'sign' && args.length === 6) {
    const [candidate, approved, keyID, pins, previous, output] = args;
    if (!process.env.LAVA_CATALOG_PRIVATE_KEY_FILE) throw new Error('Missing private key file');
    const result = signCatalog(json(candidate), json(approved),
      readFileSync(process.env.LAVA_CATALOG_PRIVATE_KEY_FILE, 'utf8'), keyID,
      {pins: json(pins), previous: previousAuthorization(previous), retiredKeys});
    writeFileSync(output, JSON.stringify(result, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  } else if (command === 'verify' && (args.length === 2 || args.length === 3)) {
    verifyCatalog(json(args[0]), json(args[1]), {previous: previousAuthorization(args[2]), retiredKeys});
    process.stdout.write('Catalog authorization verified\n');
  } else throw new Error('Usage: sign candidate.json approved.json key-id pins.json previous.json|- output.json OR verify catalog.json pins.json [previous.json]');
} catch {
  // Never print inputs or key material on a failed signing job.
  process.stderr.write('Catalog authorization failed; check arguments, inventory, pins, key and previous authorization.\n');
  process.exitCode = 1;
}
