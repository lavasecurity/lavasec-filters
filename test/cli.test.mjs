import assert from 'node:assert/strict';
import test from 'node:test';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {definitions} from '../src/authorization.mjs';

test('CLI signs reviewed inventory and requires an authorized prior document unless explicitly bootstrapping', () => {
  const directory = mkdtempSync(join(tmpdir(), 'catalog-cli-'));
  try {
    const fixture = JSON.parse(readFileSync(new URL('../fixtures/catalog-v1.json', import.meta.url)));
    const candidate = fixture.catalog;
    delete candidate.catalog_authorization;
    const approved = {revision: 1, sources: definitions(candidate.sources), guardrails: [], withdrawn_sources: []};
    const key = generateKeyPairSync('ed25519');
    const pins = {test: Buffer.from(key.publicKey.export({format: 'jwk'}).x, 'base64url').toString('base64')};
    for (const [name, value] of Object.entries({candidate, approved, pins})) {
      writeFileSync(join(directory, `${name}.json`), JSON.stringify(value));
    }
    const keyPath = join(directory, 'private.pem');
    writeFileSync(keyPath, key.privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
    const run = (...args) => spawnSync(process.execPath,
      [fileURLToPath(new URL('../src/cli.mjs', import.meta.url)), ...args],
      {cwd: directory, encoding: 'utf8', env: {...process.env, LAVA_CATALOG_PRIVATE_KEY_FILE: keyPath,
        LAVA_CATALOG_RETIRED_KEYS_FILE: ''}});
    assert.equal(run('sign', 'candidate.json', 'approved.json', 'test', 'pins.json', '-', 'signed.json').status, 0);
    assert.equal(run('verify', 'signed.json', 'pins.json').status, 0);
    assert.equal(run('verify', 'signed.json', 'pins.json', 'candidate.json').status, 1);
    assert.equal(run('sign', 'candidate.json', 'approved.json', 'test', 'pins.json', 'candidate.json', 'bad.json').status, 1);
    assert.equal(existsSync(join(directory, 'bad.json')), false);
    assert.equal(run('sign', 'candidate.json', 'approved.json', 'test', 'pins.json', 'signed.json', 'renewed.json').status, 0);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});
