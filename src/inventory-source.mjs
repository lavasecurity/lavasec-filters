import {readFileSync} from 'node:fs';
import {validateCanonical} from './build-catalog.mjs';

export function assembleInventory(index, metadata, categories) {
  const entries=index.lists.map(list=>{
    if(Object.keys(list).sort().join(',')!=='category,id,name,url') throw new Error('List entries contain only id, name, url and category');
    const extra=metadata[list.id];
    if(!extra || ['id','name','source_url','url','category','default_enabled'].some(k=>Object.hasOwn(extra,k))) {
      throw new Error('Metadata must exist and cannot override list identity or platform selection');
    }
    return {...extra,id:list.id,name:list.name,source_url:list.url,category:list.category};
  });
  const result={revision:index.revision,withdrawn_sources:index.withdrawn_sources,categories,
    sources:entries.filter(s=>s.category!=='guardrail'),guardrails:entries.filter(s=>s.category==='guardrail')};
  validateCanonical(result);
  return result;
}

export function loadCanonical() {
  const read=name=>JSON.parse(readFileSync(new URL(`../catalog/${name}.json`,import.meta.url)));
  return assembleInventory(read('lists'),read('source-metadata'),read('categories'));
}
