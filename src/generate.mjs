import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {clientIndex} from './build-catalog.mjs';
import {loadCanonical} from './inventory-source.mjs';
const canonical = loadCanonical();
const output = JSON.stringify(clientIndex(canonical), null, 2) + '\n';
const path = new URL('../dist/blocklist-catalog.json', import.meta.url);
if (process.argv.includes('--check')) {
  if (readFileSync(path, 'utf8') !== output) throw new Error('Generated client catalog is stale');
} else {
  mkdirSync(new URL('../dist/', import.meta.url), {recursive:true});
  writeFileSync(path, output);
}

const inventoryPath=new URL('../dist/inventory.json',import.meta.url);
const inventoryText=JSON.stringify(canonical,null,2)+'\n';
if(process.argv.includes('--check')) {
  if(readFileSync(inventoryPath,'utf8')!==inventoryText) throw new Error('Generated inventory is stale');
}else writeFileSync(inventoryPath,inventoryText);
