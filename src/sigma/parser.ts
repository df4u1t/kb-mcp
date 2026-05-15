import yaml from 'js-yaml';
import { SigmaRule } from '../providers/sigma.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ParsedSigmaRule {
  title: string;
  id: string;
  status?: string;
  description?: string;
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
    selections: Record<string, any>;
    condition: string;
  };
  level?: string;
  tags?: string[];
  references?: string[];
  falsepositives?: string[];
  fields?: string[];
  related?: { id: string; type: string }[];
  /** Extracted indicators from the detection logic */
  extractedIndicators: {
    field: string;
    value: string;
    modifier?: string;
  }[];
  /** Any validation warnings */
  warnings: string[];
  /** Raw YAML string */
  raw: string;
}

export interface ParseResult {
  success: boolean;
  data?: ParsedSigmaRule | ParsedSigmaRule[];
  error?: string;
  count: number;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parse a Sigma YAML rule string into a structured ParsedSigmaRule object.
 * Extracts indicators from detection selections and validates the structure.
 */
export function parseSigmaRule(yamlStr: string): ParseResult {
  try {
    const parsed = yaml.load(yamlStr) as any;
    if (!parsed || typeof parsed !== 'object') {
      return { success: false, error: 'Invalid YAML: not an object.', count: 0 };
    }

    const warnings: string[] = [];

    // Validate required fields
    if (!parsed.title) warnings.push('Rule is missing "title".');
    if (!parsed.id) warnings.push('Rule is missing "id".');
    if (!parsed.logsource || !parsed.logsource.category || !parsed.logsource.product) {
      warnings.push('Rule logsource must have at least "category" and "product".');
    }
    if (!parsed.detection || !parsed.detection.condition) {
      warnings.push('Rule detection must have a "condition".');
    }

    // Extract detection selections (everything except 'condition' and 'timeframe')
    const detection = parsed.detection || {};
    const condition = detection.condition || '';
    const selections: Record<string, any> = {};
    for (const key of Object.keys(detection)) {
      if (key !== 'condition' && key !== 'timeframe') {
        selections[key] = detection[key];
      }
    }

    // Extract indicators from selections
    const extractedIndicators: { field: string; value: string; modifier?: string }[] = [];
    for (const [selName, selValue] of Object.entries(selections)) {
      if (typeof selValue === 'object' && selValue !== null) {
        for (const [field, value] of Object.entries(selValue as Record<string, any>)) {
          if (typeof value === 'string') {
            // Check for Sigma modifiers (field|modifier)
            const [actualField, modifier] = field.split('|');
            extractedIndicators.push({
              field: actualField,
              value,
              modifier: modifier || undefined,
            });
          }
        }
      }
    }

    // Build the parsed rule
    const rule: ParsedSigmaRule = {
      title: parsed.title || '(untitled)',
      id: parsed.id || '(missing)',
      status: parsed.status,
      description: parsed.description,
      author: parsed.author,
      date: parsed.date,
      modified: parsed.modified,
      logsource: {
        category: parsed.logsource?.category || '',
        product: parsed.logsource?.product || '',
        service: parsed.logsource?.service,
        definition: parsed.logsource?.definition,
      },
      detection: {
        selections,
        condition,
      },
      level: parsed.level,
      tags: parsed.tags,
      references: parsed.references,
      falsepositives: parsed.falsepositives,
      fields: parsed.fields,
      related: parsed.related,
      extractedIndicators,
      warnings,
      raw: yamlStr,
    };

    return { success: true, data: rule, count: 1 };
  } catch (error: any) {
    return {
      success: false,
      error: `Failed to parse Sigma rule: ${error.message}`,
      count: 0,
    };
  }
}

/**
 * Parse a multi-document YAML string containing multiple Sigma rules.
 * Rules should be separated by `---` (YAML document separator).
 */
export function parseSigmaRules(yamlStr: string): ParseResult {
  try {
    const docs = yaml.loadAll(yamlStr) as any[];
    if (!docs || docs.length === 0) {
      return { success: false, error: 'No YAML documents found.', count: 0 };
    }

    const rules: ParsedSigmaRule[] = [];
    const allWarnings: string[] = [];

    for (const doc of docs) {
      if (!doc || typeof doc !== 'object') continue;
      const result = parseSigmaRule(yaml.dump(doc));
      if (result.success && result.data) {
        rules.push(result.data as ParsedSigmaRule);
        allWarnings.push(...(result.data as ParsedSigmaRule).warnings);
      }
    }

    if (rules.length === 0) {
      return { success: false, error: 'No valid Sigma rules found in the input.', count: 0 };
    }

    return {
      success: true,
      data: rules,
      count: rules.length,
    };
  } catch (error: any) {
    return {
      success: false,
      error: `Failed to parse Sigma rules: ${error.message}`,
      count: 0,
    };
  }
}

/**
 * Analyze multiple parsed Sigma rules for overlaps and conflicts.
 */
export function analyzeSigmaRules(rules: ParsedSigmaRule[]): {
  totalRules: number;
  uniqueIndicators: number;
  overlappingIndicators: { value: string; fields: string[]; rules: string[] }[];
  warnings: string[];
} {
  const indicatorMap = new Map<string, { fields: Set<string>; rules: Set<string> }>();
  const warnings: string[] = [];

  for (const rule of rules) {
    for (const ind of rule.extractedIndicators) {
      const key = `${ind.field}:${ind.value}`;
      if (!indicatorMap.has(key)) {
        indicatorMap.set(key, { fields: new Set(), rules: new Set() });
      }
      const entry = indicatorMap.get(key)!;
      entry.fields.add(ind.field);
      entry.rules.add(rule.title);
    }

    // Check for missing fields
    if (!rule.logsource.category || !rule.logsource.product) {
      warnings.push(`Rule "${rule.title}" is missing logsource category or product.`);
    }
    if (!rule.detection.condition) {
      warnings.push(`Rule "${rule.title}" is missing detection condition.`);
    }
    if (Object.keys(rule.detection.selections).length === 0) {
      warnings.push(`Rule "${rule.title}" has no detection selections.`);
    }
  }

  // Find overlapping indicators (same value used in multiple rules)
  const overlappingIndicators: { value: string; fields: string[]; rules: string[] }[] = [];
  for (const [key, entry] of indicatorMap.entries()) {
    if (entry.rules.size > 1) {
      const [field, value] = key.split(':');
      overlappingIndicators.push({
        value,
        fields: [field],
        rules: [...entry.rules],
      });
    }
  }

  return {
    totalRules: rules.length,
    uniqueIndicators: indicatorMap.size,
    overlappingIndicators,
    warnings,
  };
}
