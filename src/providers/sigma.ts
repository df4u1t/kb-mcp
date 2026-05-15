import crypto from 'crypto';
import yaml from 'js-yaml';
import { ProviderResponse } from '../types/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SigmaIndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'cve';

export interface SigmaIndicator {
  type: SigmaIndicatorType;
  value: string;
  description?: string;
  references?: string[];
  tags?: string[];
}

export type SigmaLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type SigmaStatus = 'stable' | 'test' | 'experimental';
export type SigmaOutputFormat = 'single' | 'separate';

export interface SigmaRuleOptions {
  level?: SigmaLevel;
  status?: SigmaStatus;
  author?: string;
  outputFormat?: SigmaOutputFormat;
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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map indicator types to their default Sigma logsource config */
const LOGSOURCE_MAP: Record<SigmaIndicatorType, { category: string; product: string; service?: string }> = {
  ip:     { category: 'network_connection', product: 'windows' },
  domain: { category: 'dns_query',          product: 'windows' },
  url:    { category: 'proxy',              product: 'windows' },
  hash:   { category: 'process_creation',   product: 'windows' },
  cve:    { category: 'application',        product: 'generic' },
};

/** Map indicator types to MITRE ATT&CK default tags */
const DEFAULT_TAGS: Record<SigmaIndicatorType, string[]> = {
  ip:     ['attack.command_and_control'],
  domain: ['attack.command_and_control'],
  url:    ['attack.command_and_control'],
  hash:   ['attack.execution'],
  cve:    ['attack.initial_access'],
};

/** Build a human-readable title for a rule */
function buildTitle(type: SigmaIndicatorType, value: string): string {
  const prefix: Record<SigmaIndicatorType, string> = {
    ip:     'Suspicious Network Connection to',
    domain: 'Suspicious DNS Query to',
    url:    'Suspicious URL Request to',
    hash:   'Suspicious File Hash',
    cve:    'Suspicious Activity -',
  };
  return `${prefix[type]} ${value}`;
}

/** Build a default description for a rule */
function buildDescription(type: SigmaIndicatorType, value: string, userDescription?: string): string {
  if (userDescription) return userDescription;
  const desc: Record<SigmaIndicatorType, string> = {
    ip:     `Detects network connection to a known malicious IP address: ${value}`,
    domain: `Detects DNS query to a known malicious domain: ${value}`,
    url:    `Detects request to a known malicious URL: ${value}`,
    hash:   `Detects execution of a file with a known malicious hash: ${value}`,
    cve:    `Detects potential exploitation of ${value}`,
  };
  return desc[type];
}

/** Build the detection section for a single indicator */
function buildDetection(type: SigmaIndicatorType, value: string): { [key: string]: any; condition: string } {
  const selectionName = 'selection';

  switch (type) {
    case 'ip':
      return {
        [selectionName]: {
          DestinationIp: value,
        },
        condition: selectionName,
      };

    case 'domain':
      return {
        [selectionName]: {
          'QueryName|endswith': `.${value}`,
        },
        condition: selectionName,
      };

    case 'url':
      return {
        [selectionName]: {
          'Url|contains': value,
        },
        condition: selectionName,
      };

    case 'hash':
      return {
        [selectionName]: {
          'Hashes|contains': value,
        },
        condition: selectionName,
      };

    case 'cve':
      return {
        [selectionName]: {
          'Description|contains': value,
        },
        condition: selectionName,
      };

    default:
      return {
        [selectionName]: {
          'Description|contains': value,
        },
        condition: selectionName,
      };
  }
}

/** Build a combined detection section for multiple indicators (OR logic) */
function buildCombinedDetection(indicators: SigmaIndicator[]): { [key: string]: any; condition: string } {
  const selections: Record<string, any> = {};
  const selectionNames: string[] = [];

  indicators.forEach((ind, idx) => {
    const name = `selection_${idx}`;
    selectionNames.push(name);

    switch (ind.type) {
      case 'ip':
        selections[name] = { DestinationIp: ind.value };
        break;
      case 'domain':
        selections[name] = { 'QueryName|endswith': `.${ind.value}` };
        break;
      case 'url':
        selections[name] = { 'Url|contains': ind.value };
        break;
      case 'hash':
        selections[name] = { 'Hashes|contains': ind.value };
        break;
      case 'cve':
        selections[name] = { 'Description|contains': ind.value };
        break;
    }
  });

  return {
    ...selections,
    condition: `1 of selection_*`,
  };
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
    if (!indicators || indicators.length === 0) {
      return {
        provider: 'Sigma',
        data: null,
        status: 'error',
        message: 'At least one indicator is required.',
      };
    }

    const level = options.level ?? 'high';
    const status = options.status ?? 'test';
    const author = options.author;
    const outputFormat = options.outputFormat ?? 'separate';
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

    try {
      if (outputFormat === 'single') {
        // Combine all indicators into one rule
        const allTags = [...new Set(indicators.flatMap((i) => i.tags ?? DEFAULT_TAGS[i.type]))];
        const allRefs = [...new Set(indicators.flatMap((i) => i.references ?? []))];
        const descriptions = indicators
          .map((i) => buildDescription(i.type, i.value, i.description))
          .join('; ');

        const rule: SigmaRule = {
          title: `Suspicious Activity - Multiple Indicators`,
          id: crypto.randomUUID(),
          status,
          description: descriptions,
          author,
          date: today,
          logsource: {
            category: 'application',
            product: 'generic',
            definition: 'Combined rule generated from multiple threat indicators',
          },
          detection: buildCombinedDetection(indicators),
          level,
          tags: allTags.length > 0 ? allTags : undefined,
          references: allRefs.length > 0 ? allRefs : undefined,
          falsepositives: ['Unknown'],
        };

        const yamlStr = yaml.dump(rule, {
          indent: 4,
          lineWidth: 120,
          quotingType: "'",
          forceQuotes: true,
          noRefs: true,
        });

        return {
          provider: 'Sigma',
          data: { rules: [yamlStr], count: 1 },
          status: 'success',
        };
      }

      // Separate mode — one rule per indicator
      const rules: string[] = [];

      for (const indicator of indicators) {
        const tags = indicator.tags ?? DEFAULT_TAGS[indicator.type];
        const refs = indicator.references ?? [];

        const rule: SigmaRule = {
          title: buildTitle(indicator.type, indicator.value),
          id: crypto.randomUUID(),
          status,
          description: buildDescription(indicator.type, indicator.value, indicator.description),
          author,
          date: today,
          logsource: { ...LOGSOURCE_MAP[indicator.type] },
          detection: buildDetection(indicator.type, indicator.value),
          level,
          tags,
          falsepositives: ['Unknown'],
        };

        if (refs.length > 0) {
          rule.references = refs;
        }

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
        data: { rules, count: rules.length },
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
}
