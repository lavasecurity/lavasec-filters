import {inventory} from './authorization.mjs';

export function validateCanonical(canonical) {
  const approved=inventory(canonical);
  for(const s of [...canonical.sources,...canonical.guardrails]) {
    if(s.redistribution_mode!=='source_url_only' ||
       (s.license_name.startsWith('GPL-') && (s.default_enabled || !s.license_text_url)) ||
       (s.provider==='stevenblack' && s.default_enabled && s.counsel_status!=='approved')) {
      throw new Error('Canonical inventory violates source-only/default/license policy');
    }
  }
  return approved;
}

// Infra supplies observations, never membership, URLs, defaults or other definitions.
// Binding observations to URL/parser prevents carrying old cache identities across edits.
export function buildCatalog(canonical, observations = {}, now = new Date()) {
  const approved = validateCanonical(canonical);
  const entries = [...(observations.sources ?? []), ...(observations.guardrails ?? [])];
  const generated_at = now.toISOString();
  const catalog_version = generated_at.replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const project = definition => {
    const matches = entries.filter(s => s.id === definition.id && s.source_url === definition.source_url &&
      s.parse_format === definition.parse_format);
    const observation = matches.length === 1 ? matches[0] : {};
    const result = {...definition, version_id: `${definition.id}-unobserved`, entry_count: 0,
      byte_size: 0, source_hash: '', normalized_hash: '', accepted_source_hashes: [],
      published_at: '1970-01-01T00:00:00.000Z'};
    for (const field of ['version_id', 'entry_count', 'byte_size', 'source_hash', 'normalized_hash',
      'accepted_source_hashes', 'published_at']) {
      if (observation[field] !== undefined) result[field] = observation[field];
    }
    return result;
  };
  return {schema_version: 2, catalog_version, generated_at, catalog_definition_revision: approved.revision,
    sources: approved.sources.map(project), guardrails: approved.guardrails.map(project),
    withdrawn_sources: approved.withdrawn_sources};
}

// Compatibility projection for existing app code generators and the public docs site.
export function clientIndex(canonical) {
  validateCanonical(canonical);
  return {schema_version: 1,
    _generated: 'DO NOT EDIT — generated from lavasecurity/lavasec-filters/catalog/inventory.json',
    categories: canonical.categories,
    sources: canonical.sources.map(s => ({id:s.id,name:s.name,provider:s.provider,category:s.category,
      license:s.license_name,license_text_url:s.license_text_url,source_url:s.source_url,
      project_url:s.project_url,parse_format:s.parse_format === 'auto' ? 'domain_list' : s.parse_format,
      redistribution_mode:s.redistribution_mode,warning_level:s.risk_level,
      default_enabled:s.default_enabled,size_hint:s.size_hint,counsel_status:s.counsel_status}))};
}
