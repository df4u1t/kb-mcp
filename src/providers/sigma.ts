import crypto from 'crypto';
import yaml from 'js-yaml';
import { ProviderResponse } from '../types/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SigmaIndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'cve' | 'email' | 'registry' | 'mutex' | 'ip_range' | 'keyword';

export type SigmaMatchType = 'exact' | 'contains' | 'startswith' | 'endswith';

export interface SigmaIndicator {
  type: SigmaIndicatorType;
  value: string;
  description?: string;
  references?: string[];
  tags?: string[];
  matchType?: SigmaMatchType;
  keywordFields?: string[];
  selectionName?: string;
}

export type SigmaLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type SigmaStatus = 'stable' | 'test' | 'experimental';
export type SigmaOutputFormat = 'single' | 'separate';
export type SigmaPlatform = 'windows' | 'linux' | 'macos' | 'cross';

export interface SigmaLogsourceOverride {
  category?: string;
  product?: string;
  service?: string;
  definition?: string;
}

export interface SigmaRuleOptions {
  level?: SigmaLevel;
  status?: SigmaStatus;
  author?: string;
  outputFormat?: SigmaOutputFormat;
  platform?: SigmaPlatform;
  logsource?: SigmaLogsourceOverride;
  falsepositives?: string[];
  ruleId?: string;
  fields?: string[];
  mitreAttack?: string[];
  related?: string[];
  condition?: string;
}

export interface SigmaRule {
  title: string;
  id: string;
  status?: string;
  description?: string;
  references?: string[];
  author?: string;
  date?: string;
  modified?: string;
  logsource: {
    category: string;
    product: string;
    service?: string;
    definition?: string;
  };
  detection: {
    [key: string]: any;
    condition: string;
  };
  fields?: string[];
  falsepositives?: string[];
  level?: string;
  tags?: string[];
  related?: string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map indicator types to their default Sigma logsource config */
const LOGSOURCE_MAP: Record<SigmaIndicatorType, { category: string; product: string; service?: string; definition?: string }> = {
  ip:       { category: 'network_connection', product: 'windows' },
  domain:   { category: 'dns_query',          product: 'windows' },
  url:      { category: 'proxy',              product: 'windows' },
  hash:     { category: 'process_creation',   product: 'windows' },
  cve:      { category: 'application',        product: 'generic' },
  email:    { category: 'email',              product: 'windows' },
  registry: { category: 'registry_set',       product: 'windows' },
  mutex:    { category: 'process_creation',   product: 'windows' },
  ip_range: { category: 'network_connection', product: 'windows' },
  keyword:  { category: 'application',        product: 'generic' },
};

/** Platform-specific logsource overrides */
const LOGSOURCE_PLATFORMS: Record<SigmaPlatform, { product: string; definition?: string }> = {
  windows: { product: 'windows' },
  linux:   { product: 'linux',   definition: 'Linux auditd or syslog' },
  macos:   { product: 'macos',   definition: 'macOS unified log' },
  cross:   { product: 'generic', definition: 'Cross-platform log source' },
};

/** Map indicator types to MITRE ATT&CK default tags */
const DEFAULT_TAGS: Record<SigmaIndicatorType, string[]> = {
  ip:       ['attack.command_and_control'],
  domain:   ['attack.command_and_control'],
  url:      ['attack.command_and_control'],
  hash:     ['attack.execution'],
  cve:      ['attack.initial_access'],
  email:    ['attack.initial_access'],
  registry: ['attack.persistence'],
  mutex:    ['attack.execution'],
  ip_range: ['attack.command_and_control'],
  keyword:  ['attack.execution'],
};

/** Default match type per indicator type */
const DEFAULT_MATCH_TYPE: Record<SigmaIndicatorType, SigmaMatchType> = {
  ip:       'exact',
  domain:   'endswith',
  url:      'contains',
  hash:     'contains',
  cve:      'contains',
  email:    'contains',
  registry: 'contains',
  mutex:    'contains',
  ip_range: 'startswith',
  keyword:  'contains',
};

/** Build a human-readable title for a rule */
function buildTitle(type: SigmaIndicatorType, value: string): string {
  const prefix: Record<SigmaIndicatorType, string> = {
    ip:       'Suspicious Network Connection to',
    domain:   'Suspicious DNS Query to',
    url:      'Suspicious URL Request to',
    hash:     'Suspicious File Hash',
    cve:      'Suspicious Activity -',
    email:    'Suspicious Email from',
    registry: 'Suspicious Registry Key',
    mutex:    'Suspicious Mutex',
    ip_range: 'Suspicious Network Traffic to',
    keyword:  'Suspicious Activity -',
  };
  return `${prefix[type]} ${value}`;
}

/** Build a default description for a rule */
function buildDescription(type: SigmaIndicatorType, value: string, userDescription?: string): string {
  if (userDescription) return userDescription;
  const desc: Record<SigmaIndicatorType, string> = {
    ip:       `Detects network connection to a known malicious IP address: ${value}`,
    domain:   `Detects DNS query to a known malicious domain: ${value}`,
    url:      `Detects request to a known malicious URL: ${value}`,
    hash:     `Detects execution of a file with a known malicious hash: ${value}`,
    cve:      `Detects potential exploitation of ${value}`,
    email:    `Detects email from a known malicious sender: ${value}`,
    registry: `Detects modification of a suspicious registry key: ${value}`,
    mutex:    `Detects creation of a known malicious mutex: ${value}`,
    ip_range: `Detects network traffic to a known malicious IP range: ${value}`,
    keyword:  `Detects activity matching keyword: ${value}`,
  };
  return desc[type];
}

/**
 * Build a field:value pair respecting the match type.
 * Returns the field name with optional Sigma modifier and the value.
 */
function buildFieldValue(field: string, value: string, matchType: SigmaMatchType): Record<string, string> {
  switch (matchType) {
    case 'exact':
      return { [field]: value };
    case 'contains':
      return { [`${field}|contains`]: value };
    case 'startswith':
      return { [`${field}|startswith`]: value };
    case 'endswith':
      return { [`${field}|endswith`]: value };
  }
}

/**
 * Build keyword detection across multiple fields.
 * Creates a selection with the keyword value in each specified field.
 */
function buildKeywordDetection(
  value: string,
  fields: string[],
  matchType: SigmaMatchType,
): Record<string, any> {
  const selection: Record<string, any> = {};
  for (const field of fields) {
    Object.assign(selection, buildFieldValue(field, value, matchType));
  }
  return selection;
}

/** Get the default field name for an indicator type */
function getFieldForType(type: SigmaIndicatorType): string {
  switch (type) {
    case 'ip':       return 'DestinationIp';
    case 'domain':   return 'QueryName';
    case 'url':      return 'Url';
    case 'hash':     return 'Hashes';
    case 'cve':      return 'Description';
    case 'email':    return 'SenderMail';
    case 'registry': return 'TargetObject';
    case 'mutex':    return 'Mutex';
    case 'ip_range': return 'DestinationIp';
    case 'keyword':  return 'Description';
  }
}

/** Build the detection section for a single indicator */
function buildDetection(
  type: SigmaIndicatorType,
  value: string,
  matchType?: SigmaMatchType,
  keywordFields?: string[],
  selectionName?: string,
): { [key: string]: any; condition: string } {
  const name = selectionName ?? 'selection';
  const mt = matchType ?? DEFAULT_MATCH_TYPE[type];
  const field = getFieldForType(type);

  // For domain endswith, prepend a dot to match subdomains
  const adjustedValue = type === 'domain' && mt === 'endswith' ? `.${value}` : value;

  // Keyword type with custom fields — search across multiple fields
  if (type === 'keyword' && keywordFields && keywordFields.length > 0) {
    return {
      [name]: buildKeywordDetection(adjustedValue, keywordFields, mt),
      condition: name,
    };
  }

  return {
    [name]: buildFieldValue(field, adjustedValue, mt),
    condition: name,
  };
}

/** Build a combined detection section for multiple indicators (OR logic) */
function buildCombinedDetection(
  indicators: SigmaIndicator[],
  customCondition?: string,
): { [key: string]: any; condition: string } {
  const selections: Record<string, any> = {};

  indicators.forEach((ind, idx) => {
    const name = ind.selectionName ?? `selection_${idx}`;
    const mt = ind.matchType ?? DEFAULT_MATCH_TYPE[ind.type];
    const field = getFieldForType(ind.type);
    const adjustedValue = ind.type === 'domain' && mt === 'endswith' ? `.${ind.value}` : ind.value;

    if (ind.type === 'keyword' && ind.keywordFields && ind.keywordFields.length > 0) {
      selections[name] = buildKeywordDetection(adjustedValue, ind.keywordFields, mt);
    } else {
      selections[name] = buildFieldValue(field, adjustedValue, mt);
    }
  });

  return {
    ...selections,
    condition: customCondition ?? '1 of selection_*',
  };
}

/** Resolve the final logsource config */
function resolveLogsource(
  type: SigmaIndicatorType,
  platform: SigmaPlatform,
  logsourceOverride?: SigmaLogsourceOverride,
): { category: string; product: string; service?: string; definition?: string } {
  const base = { ...LOGSOURCE_MAP[type] };
  const platformCfg = LOGSOURCE_PLATFORMS[platform];

  // Apply platform product override
  base.product = platformCfg.product;

  // Apply platform definition if set
  if (platformCfg.definition) {
    base.definition = platformCfg.definition;
  }

  // Apply user overrides on top
  if (logsourceOverride) {
    if (logsourceOverride.category) base.category = logsourceOverride.category;
    if (logsourceOverride.product) base.product = logsourceOverride.product;
    if (logsourceOverride.service) base.service = logsourceOverride.service;
    if (logsourceOverride.definition) base.definition = logsourceOverride.definition;
  }

  return base;
}

// ---------------------------------------------------------------------------
// Type Normalization
// ---------------------------------------------------------------------------

/**
 * Map of common type aliases to internal SigmaIndicatorType values.
 * Handles case-insensitive matching and common OTX/VT/API type names.
 */
const TYPE_ALIASES: Record<string, SigmaIndicatorType> = {
  // IPv4 / IPv6
  'ipv4': 'ip',
  'ipv6': 'ip',
  'ip_address': 'ip',
  // Domain / hostname
  'domain': 'domain',
  'hostname': 'domain',
  'host_name': 'domain',
  'fqdn': 'domain',
  // URL
  'url': 'url',
  'uri': 'url',
  // Hash variants
  'hash': 'hash',
  'filehash': 'hash',
  'file_hash': 'hash',
  'md5': 'hash',
  'sha1': 'hash',
  'sha256': 'hash',
  'filehash-md5': 'hash',
  'filehash-sha1': 'hash',
  'filehash-sha256': 'hash',
  'filehash-sha512': 'hash',
  'filehash-imphash': 'hash',
  // CVE
  'cve': 'cve',
  'cve_id': 'cve',
  // Email
  'email': 'email',
  'mail': 'email',
  'sender': 'email',
  // Registry
  'registry': 'registry',
  'registry_key': 'registry',
  'regkey': 'registry',
  // Mutex
  'mutex': 'mutex',
  // IP range / CIDR
  'ip_range': 'ip_range',
  'cidr': 'ip_range',
  'subnet': 'ip_range',
  'network': 'ip_range',
  // Keyword
  'keyword': 'keyword',
  'text': 'keyword',
  'string': 'keyword',
};

/**
 * Normalize an indicator type string to the internal SigmaIndicatorType.
 * Handles case-insensitive matching and common aliases.
 *
 * @param rawType  The raw type string from input (e.g., "IPv4", "FileHash-MD5", "URL")
 * @returns        The normalized SigmaIndicatorType, or undefined if unrecognized
 */
function normalizeIndicatorType(rawType: string): SigmaIndicatorType | undefined {
  if (!rawType) return undefined;

  // Try direct match first (case-insensitive)
  const lower = rawType.toLowerCase().trim();
  const validTypes: SigmaIndicatorType[] = ['ip', 'domain', 'url', 'hash', 'cve', 'email', 'registry', 'mutex', 'ip_range', 'keyword'];
  if (validTypes.includes(lower as SigmaIndicatorType)) {
    return lower as SigmaIndicatorType;
  }

  // Try alias map
  return TYPE_ALIASES[lower];
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Valid indicator type patterns for basic format checking */
const INDICATOR_PATTERNS: Partial<Record<SigmaIndicatorType, RegExp>> = {
  ip:       /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+::[a-fA-F0-9:]*|[a-fA-F0-9:]+:[a-fA-F0-9:]+)$/,
  domain:   /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
  hash:     /^[a-fA-F0-9]{6,128}$/,
  cve:      /^CVE-\d{4}-\d{4,}$/i,
  email:    /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
};

/** Valid MITRE ATT&CK technique ID pattern */
const MITRE_TECHNIQUE_PATTERN = /^attack\.t\d{4}(\.\d{3})?$/i;

/**
 * Validate a single Sigma indicator.
 * Returns an array of error messages (empty = valid).
 * Note: indicator.type will be normalized in-place if it matches a known alias.
 */
function validateIndicator(indicator: SigmaIndicator): string[] {
  const errors: string[] = [];

  if (!indicator.type) {
    errors.push('Indicator is missing "type" field.');
    return errors;
  }

  if (!indicator.value || typeof indicator.value !== 'string' || indicator.value.trim().length === 0) {
    errors.push(`Indicator of type "${indicator.type}" is missing a valid "value" field.`);
    return errors;
  }

  // Normalize type (case-insensitive alias matching)
  const normalizedType = normalizeIndicatorType(indicator.type);
  if (!normalizedType) {
    const validTypes: SigmaIndicatorType[] = ['ip', 'domain', 'url', 'hash', 'cve', 'email', 'registry', 'mutex', 'ip_range', 'keyword'];
    errors.push(`Unknown indicator type "${indicator.type}". Valid types: ${validTypes.join(', ')}`);
    return errors;
  }

  // Apply normalized type back to the indicator
  indicator.type = normalizedType;

  // Format validation for known patterns
  const pattern = INDICATOR_PATTERNS[indicator.type];
  if (pattern && !pattern.test(indicator.value.trim())) {
    errors.push(`"${indicator.value}" does not look like a valid ${indicator.type.toUpperCase()} format.`);
  }

  // Validate matchType if provided
  if (indicator.matchType) {
    const validMatchTypes: SigmaMatchType[] = ['exact', 'contains', 'startswith', 'endswith'];
    if (!validMatchTypes.includes(indicator.matchType)) {
      errors.push(`Invalid matchType "${indicator.matchType}". Valid: ${validMatchTypes.join(', ')}`);
    }
  }

  // Validate MITRE tags
  if (indicator.tags) {
    for (const tag of indicator.tags) {
      if (tag.startsWith('attack.') && !MITRE_TECHNIQUE_PATTERN.test(tag)) {
        errors.push(`Tag "${tag}" looks like a MITRE ATT&CK technique but has invalid format. Use "attack.tXXXX" or "attack.tXXXX.XXX".`);
      }
    }
  }

  return errors;
}

/**
 * Validate all indicators and return consolidated errors.
 */
function validateIndicators(indicators: SigmaIndicator[]): string[] {
  if (!indicators || !Array.isArray(indicators)) {
    return ['"indicators" must be a non-empty array.'];
  }
  if (indicators.length === 0) {
    return ['At least one indicator is required.'];
  }

  const allErrors: string[] = [];
  for (let i = 0; i < indicators.length; i++) {
    const errs = validateIndicator(indicators[i]);
    for (const err of errs) {
      allErrors.push(`Indicator [${i}]: ${err}`);
    }
  }
  return allErrors;
}

/**
 * Generate a deterministic UUID v4-style string from a seed string.
 * Same seed always produces the same UUID.
 */
function deterministicUUID(seed: string): string {
  const hash = crypto.createHash('sha256').update(seed).digest('hex');
  // Format as UUID v4: 8-4-4-4-12 with version nibble set to 4
  return [
    hash.substring(0, 8),
    hash.substring(8, 12),
    `4${hash.substring(13, 16)}`,
    `8${hash.substring(17, 20)}`,
    hash.substring(20, 32),
  ].join('-');
}

/**
 * Validate the final Sigma rule structure against Sigma spec requirements.
 * Returns an array of warnings (empty = fully spec-compliant).
 */
function validateSigmaRule(rule: SigmaRule): string[] {
  const warnings: string[] = [];

  if (!rule.title) warnings.push('Rule is missing "title".');
  if (!rule.id) warnings.push('Rule is missing "id".');
  if (!rule.logsource || !rule.logsource.category || !rule.logsource.product) {
    warnings.push('Rule logsource must have at least "category" and "product".');
  }
  if (!rule.detection || !rule.detection.condition) {
    warnings.push('Rule detection must have a "condition".');
  }
  if (rule.detection) {
    const selectionKeys = Object.keys(rule.detection).filter(k => k !== 'condition');
    if (selectionKeys.length === 0) {
      warnings.push('Rule detection has no selections (only condition).');
    }
  }

  return warnings;
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export class SigmaRuleGenerator {
  /**
   * Generate Sigma detection rules from a list of threat indicators.
   *
   * @param indicators  Array of enriched indicators
   * @param options     Rule generation options
   * @returns           ProviderResponse containing the generated YAML rule(s)
   */
  generateFromIndicators(
    indicators: SigmaIndicator[],
    options: SigmaRuleOptions = {},
  ): ProviderResponse {
    // --- Validation ---
    const validationErrors = validateIndicators(indicators);
    if (validationErrors.length > 0) {
      return {
        provider: 'Sigma',
        data: null,
        status: 'error',
        message: validationErrors.join('; '),
      };
    }

    const level = options.level ?? 'high';
    const status = options.status ?? 'test';
    const author = options.author;
    const outputFormat = options.outputFormat ?? 'separate';
    const platform = options.platform ?? 'windows';
    const logsourceOverride = options.logsource;
    const falsepositives = options.falsepositives ?? ['Unknown'];
    const ruleId = options.ruleId;
    const fields = options.fields;
    const mitreAttack = options.mitreAttack;
    const related = options.related;
    const customCondition = options.condition;
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

    try {
      if (outputFormat === 'single') {
        // Combine all indicators into one rule
        const allTags = [...new Set([
          ...(mitreAttack ?? []),
          ...indicators.flatMap((i) => i.tags ?? DEFAULT_TAGS[i.type]),
        ])];
        const allRefs = [...new Set(indicators.flatMap((i) => i.references ?? []))];
        const descriptions = indicators
          .map((i) => buildDescription(i.type, i.value, i.description))
          .join('; ');

        // Deterministic ID based on all indicator values
        const idSeed = indicators.map(i => `${i.type}:${i.value}`).sort().join('|');
        const id = ruleId ?? deterministicUUID(`sigma-single-${idSeed}`);

        const rule: SigmaRule = {
          title: 'Suspicious Activity - Multiple Indicators',
          id,
          status,
          description: descriptions,
          author,
          date: today,
          modified: today,
          logsource: resolveLogsource(indicators[0].type, platform, logsourceOverride),
          detection: buildCombinedDetection(indicators, customCondition),
          level,
          tags: allTags.length > 0 ? allTags : undefined,
          references: allRefs.length > 0 ? allRefs : undefined,
          falsepositives,
          fields,
          related: related && related.length > 0 ? related.map(r => ({ id: r, type: 'similar' })) as any : undefined,
        };

        const warnings = validateSigmaRule(rule);
        const yamlStr = yaml.dump(rule, {
          indent: 4,
          lineWidth: 120,
          quotingType: "'",
          forceQuotes: true,
          noRefs: true,
        });

        return {
          provider: 'Sigma',
          data: { rules: [yamlStr], count: 1, warnings: warnings.length > 0 ? warnings : undefined },
          status: 'success',
        };
      }

      // Separate mode — one rule per indicator
      const rules: string[] = [];
      const allWarnings: string[] = [];

      for (const indicator of indicators) {
        const tags = [...new Set([
          ...(mitreAttack ?? []),
          ...(indicator.tags ?? DEFAULT_TAGS[indicator.type]),
        ])];
        const refs = indicator.references ?? [];

        // Deterministic ID per indicator
        const id = ruleId ?? deterministicUUID(`sigma-${indicator.type}:${indicator.value}`);

        const rule: SigmaRule = {
          title: buildTitle(indicator.type, indicator.value),
          id,
          status,
          description: buildDescription(indicator.type, indicator.value, indicator.description),
          author,
          date: today,
          modified: today,
          logsource: resolveLogsource(indicator.type, platform, logsourceOverride),
          detection: buildDetection(indicator.type, indicator.value, indicator.matchType, indicator.keywordFields, indicator.selectionName),
          level,
          tags,
          falsepositives,
          fields,
          related: related && related.length > 0 ? related.map(r => ({ id: r, type: 'similar' })) as any : undefined,
        };

        if (refs.length > 0) {
          rule.references = refs;
        }

        const warnings = validateSigmaRule(rule);
        allWarnings.push(...warnings.map(w => `[${indicator.type}:${indicator.value}] ${w}`));

        rules.push(
          yaml.dump(rule, {
            indent: 4,
            lineWidth: 120,
            quotingType: "'",
            forceQuotes: true,
            noRefs: true,
          }),
        );
      }

      return {
        provider: 'Sigma',
        data: {
          rules,
          count: rules.length,
          warnings: allWarnings.length > 0 ? [...new Set(allWarnings)] : undefined,
        },
        status: 'success',
      };
    } catch (error: any) {
      return {
        provider: 'Sigma',
        data: null,
        status: 'error',
        message: `Failed to generate Sigma rules: ${error.message}`,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Cross-Provider Enrichment
  // ---------------------------------------------------------------------------

  /**
   * Extract Sigma indicators from a VirusTotal response.
   */
  extractFromVTResponse(data: any): SigmaIndicator[] {
    const indicators: SigmaIndicator[] = [];
    if (!data) return indicators;

    const attrs = data?.data?.attributes;
    if (!attrs) return indicators;

    // File report — extract hashes
    if (attrs.md5 || attrs.sha1 || attrs.sha256) {
      indicators.push({
        type: 'hash',
        value: attrs.sha256 || attrs.sha1 || attrs.md5,
        description: `VT file analysis: ${attrs?.meaningful_name || 'unknown file'}`,
        tags: ['attack.execution'],
      });
    }

    // Domain/IP report — extract resolutions
    if (attrs?.resolutions) {
      for (const res of attrs.resolutions.slice(0, 10)) {
        if (res.ip_address) {
          indicators.push({ type: 'ip', value: res.ip_address, tags: ['attack.command_and_control'] });
        }
      }
    }

    // URL report
    if (attrs?.url) {
      indicators.push({
        type: 'url',
        value: attrs.url,
        description: `VT URL analysis: ${attrs?.title || ''}`,
        tags: ['attack.command_and_control'],
      });
    }

    return indicators;
  }

  /**
   * Extract Sigma indicators from a Shodan response.
   */
  extractFromShodanResponse(data: any): SigmaIndicator[] {
    const indicators: SigmaIndicator[] = [];
    if (!data) return indicators;

    // Host info — extract IP and open ports
    if (data?.ip_str) {
      indicators.push({
        type: 'ip',
        value: data.ip_str,
        description: `Shodan host: ${data.ip_str} — ${data?.data?.[0]?.product || 'unknown service'}`,
        tags: ['attack.command_and_control'],
      });
    }

    // Hostnames
    if (data?.hostnames) {
      for (const hn of data.hostnames.slice(0, 5)) {
        indicators.push({
          type: 'domain',
          value: hn,
          description: `Shodan hostname for ${data.ip_str}`,
          tags: ['attack.command_and_control'],
        });
      }
    }

    return indicators;
  }

  /**
   * Extract Sigma indicators from an NVD CVE response.
   */
  extractFromNVDResponse(data: any): SigmaIndicator[] {
    const indicators: SigmaIndicator[] = [];
    if (!data) return indicators;

    const vulns = data?.vulnerabilities || [];
    for (const vuln of vulns.slice(0, 20)) {
      const cve = vuln?.cve;
      if (!cve?.id) continue;

      const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
      const severity = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity?.toLowerCase() || 'high';

      indicators.push({
        type: 'cve',
        value: cve.id,
        description: desc.substring(0, 500),
        references: cve.references?.map((r: any) => r.url) || [],
        tags: ['attack.initial_access', `attack.t1190`],
      });
    }

    return indicators;
  }

  /**
   * Extract Sigma indicators from an AlienVault OTX response.
   */
  extractFromOTXResponse(data: any): SigmaIndicator[] {
    const indicators: SigmaIndicator[] = [];
    if (!data) return indicators;

    // Pulse details — extract indicators from pulse
    if (data?.indicators) {
      for (const ind of data.indicators.slice(0, 30)) {
        const type = ind.type?.toLowerCase();
        if (type === 'ipv4' || type === 'ipv6') {
          indicators.push({
            type: 'ip',
            value: ind.indicator,
            description: `OTX pulse indicator: ${ind.title || ''}`,
            tags: ['attack.command_and_control'],
          });
        } else if (type === 'domain' || type === 'hostname') {
          indicators.push({
            type: 'domain',
            value: ind.indicator,
            description: `OTX pulse indicator: ${ind.title || ''}`,
            tags: ['attack.command_and_control'],
          });
        } else if (type === 'url') {
          indicators.push({
            type: 'url',
            value: ind.indicator,
            description: `OTX pulse indicator: ${ind.title || ''}`,
            tags: ['attack.command_and_control'],
          });
        } else if (type === 'filehash' || type === 'md5' || type === 'sha1' || type === 'sha256') {
          indicators.push({
            type: 'hash',
            value: ind.indicator,
            description: `OTX pulse file hash: ${ind.title || ''}`,
            tags: ['attack.execution'],
          });
        }
      }
    }

    // Search results
    if (data?.results) {
      for (const pulse of data.results.slice(0, 10)) {
        if (pulse?.indicators) {
          for (const ind of pulse.indicators.slice(0, 10)) {
            const type = ind.type?.toLowerCase();
            if (type === 'ipv4' || type === 'ipv6') {
              indicators.push({ type: 'ip', value: ind.indicator, tags: ['attack.command_and_control'] });
            } else if (type === 'domain' || type === 'hostname') {
              indicators.push({ type: 'domain', value: ind.indicator, tags: ['attack.command_and_control'] });
            } else if (type === 'url') {
              indicators.push({ type: 'url', value: ind.indicator, tags: ['attack.command_and_control'] });
            } else if (type === 'filehash' || type === 'sha256') {
              indicators.push({ type: 'hash', value: ind.indicator, tags: ['attack.execution'] });
            }
          }
        }
      }
    }

    return indicators;
  }

  /**
   * Generate Sigma rules from a provider's response data.
   *
   * @param providerName  Name of the provider (e.g., 'VirusTotal', 'NVD', 'Shodan', 'OTX')
   * @param data          The response data from the provider
   * @param options       Rule generation options
   * @returns             ProviderResponse containing the generated YAML rule(s)
   */
  generateFromProviderResult(
    providerName: string,
    data: any,
    options: SigmaRuleOptions = {},
  ): ProviderResponse {
    let indicators: SigmaIndicator[] = [];

    switch (providerName.toLowerCase()) {
      case 'virustotal':
      case 'vt':
        indicators = this.extractFromVTResponse(data);
        break;
      case 'shodan':
        indicators = this.extractFromShodanResponse(data);
        break;
      case 'nvd':
        indicators = this.extractFromNVDResponse(data);
        break;
      case 'alienvault':
      case 'otx':
        indicators = this.extractFromOTXResponse(data);
        break;
      default:
        return {
          provider: 'Sigma',
          data: null,
          status: 'error',
          message: `Unknown provider: "${providerName}". Supported: VirusTotal, Shodan, NVD, AlienVault OTX`,
        };
    }

    if (indicators.length === 0) {
      return {
        provider: 'Sigma',
        data: null,
        status: 'error',
        message: `No indicators could be extracted from the ${providerName} response.`,
      };
    }

    return this.generateFromIndicators(indicators, options);
  }
}
