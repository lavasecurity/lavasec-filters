import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {clientIndex} from './build-catalog.mjs';
const canonical = JSON.parse(readFileSync(new URL('../catalog/inventory.json', import.meta.url)));
const output = JSON.stringify(clientIndex(canonical), null, 2) + '\n';
const path = new URL('../dist/blocklist-catalog.json', import.meta.url);
if (process.argv.includes('--check')) {
  if (readFileSync(path, 'utf8') !== output) throw new Error('Generated client catalog is stale');
} else {
  mkdirSync(new URL('../dist/', import.meta.url), {recursive:true});
  writeFileSync(path, output);
}
