import {inventory} from './authorization.mjs';
import {isDeepStrictEqual} from 'node:util';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

export function checkRevision(previous, current) {
  const before=inventory(previous), after=inventory(current);
  if(after.revision<before.revision ||
    (!isDeepStrictEqual({...after,revision:before.revision},before) && after.revision===before.revision)) {
    throw new Error('Definition changes require a higher catalog revision');
  }
  const active=new Set([...after.sources,...after.guardrails].map(s=>s.id));
  if(!before.withdrawn_sources.every(id=>after.withdrawn_sources.includes(id)) ||
    ![...before.sources,...before.guardrails].every(s=>active.has(s.id)||after.withdrawn_sources.includes(s.id))) {
    throw new Error('Retired identities require cumulative withdrawals');
  }
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href){
  const base=process.env.BASE_SHA;
  if(!/^[a-f0-9]{40}$/.test(base??'')) throw new Error('Expected immutable base SHA');
  // The initial migration has no base inventory; later authoring PRs always do.
  const files=execFileSync('git',['ls-tree','--name-only',base,'catalog/inventory.json'],{encoding:'utf8'});
  if(files.trim()) checkRevision(JSON.parse(execFileSync('git',['show',`${base}:catalog/inventory.json`],{encoding:'utf8'})),
    JSON.parse(readFileSync('catalog/inventory.json')));
}
