import {readFileSync, writeFileSync, mkdirSync, existsSync} from 'node:fs';
import {signCatalog, MAX_BYTES} from './authorization.mjs';
async function download(url, token) {
  if (!url || new URL(url).protocol !== 'https:') throw new Error('Configure an HTTPS catalog endpoint');
  const response = await fetch(url, {redirect: 'error', signal: AbortSignal.timeout(30000),
    headers: token ? {Authorization: `Bearer ${token}`} : {}});
  if (!response.ok || !response.body) throw new Error('Catalog endpoint unavailable');
  const chunks=[];let count=0;
  for await (const chunk of response.body) {count+=chunk.length;if(count>MAX_BYTES)throw new Error('Catalog exceeds byte limit');chunks.push(chunk);}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
try {
  const approved=JSON.parse(readFileSync('policy/approved-inventory.json'));
  const pins=JSON.parse(readFileSync('policy/public-keys.json'));
  const retiredKeys=existsSync('policy/retired-keys.json')?JSON.parse(readFileSync('policy/retired-keys.json')):{};
  const candidate=await download(process.env.CATALOG_CANDIDATE_URL,process.env.CATALOG_CANDIDATE_TOKEN);
  // Bootstrap is an explicit commissioning choice, never an automatic reaction to a failed read.
  const previous=process.env.CATALOG_BOOTSTRAP==='true'?undefined:
    (await download(process.env.CATALOG_CURRENT_URL)).catalog_authorization;
  if (process.env.CATALOG_BOOTSTRAP!=='true' && !previous) throw new Error('Previous authorization missing');
  const result=signCatalog(candidate,approved,process.env.CATALOG_SIGNING_PRIVATE_KEY,
    process.env.CATALOG_SIGNING_KEY_ID,{pins,previous,retiredKeys});
  mkdirSync('out',{recursive:true});
  writeFileSync('out/catalog.json',JSON.stringify(result,null,2)+'\n',{mode:0o600});
} catch {
  // Private key parse errors can contain secret input. Never echo error objects in this job.
  process.stderr.write('Signing failed; check inventory, pins, endpoint access and validity. No artifact published.\n');
  process.exitCode=1;
}
