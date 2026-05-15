import { ParsedSigmaRule, parseSigmaRule, parseSigmaRules } from '../parser.js';
import { convertToSplunk, convertToSplunkAlert } from './splunk.js';
import { convertToElasticEQL, convertToElasticDSL } from './elastic.js';
import { convertToQRadar, convertToQRadarRule } from './qradar.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SiemTarget = 'splunk' | 'splunk_alert' | 'elastic_eql' | 'elastic_dsl' | 'qradar' | 'qradar_rule';

export interface ConversionResult {
  success: boolean;
  target: SiemTarget;
  query?: string;
  queryObject?: object;
  error?: string;
  ruleTitle?: string;
  ruleId?: string;
}

// ---------------------------------------------------------------------------
// Converter
// ---------------------------------------------------------------------------

/**
 * Convert a Sigma YAML rule string to a target SIEM format.
 *
 * @param yamlStr   The Sigma YAML rule content
 * @param target    The target SIEM format
 * @returns         ConversionResult with the converted query
 */
export function convertSigmaRule(yamlStr: string, target: SiemTarget): ConversionResult {
  // Parse the rule first
  const parseResult = parseSigmaRule(yamlStr);
  if (!parseResult.success || !parseResult.data) {
    return {
      success: false,
      target,
      error: parseResult.error || 'Failed to parse Sigma rule.',
    };
  }

  const rule = parseResult.data as ParsedSigmaRule;

  try {
    switch (target) {
      case 'splunk': {
        const query = convertToSplunk(rule);
        return { success: true, target, query, ruleTitle: rule.title, ruleId: rule.id };
      }
      case 'splunk_alert': {
        const query = convertToSplunkAlert(rule);
        return { success: true, target, query, ruleTitle: rule.title, ruleId: rule.id };
      }
      case 'elastic_eql': {
        const query = convertToElasticEQL(rule);
        return { success: true, target, query, ruleTitle: rule.title, ruleId: rule.id };
      }
      case 'elastic_dsl': {
        const queryObject = convertToElasticDSL(rule);
        return { success: true, target, queryObject, ruleTitle: rule.title, ruleId: rule.id };
      }
      case 'qradar': {
        const query = convertToQRadar(rule);
        return { success: true, target, query, ruleTitle: rule.title, ruleId: rule.id };
      }
      case 'qradar_rule': {
        const query = convertToQRadarRule(rule);
        return { success: true, target, query, ruleTitle: rule.title, ruleId: rule.id };
      }
      default:
        return {
          success: false,
          target,
          error: `Unknown target SIEM format: "${target}". Supported: splunk, splunk_alert, elastic_eql, elastic_dsl, qradar, qradar_rule`,
        };
    }
  } catch (error: any) {
    return {
      success: false,
      target,
      error: `Conversion error: ${error.message}`,
      ruleTitle: rule.title,
      ruleId: rule.id,
    };
  }
}

/**
 * Convert multiple Sigma rules to a target SIEM format.
 */
export function convertSigmaRules(yamlStr: string, target: SiemTarget): ConversionResult[] {
  const parseResult = parseSigmaRules(yamlStr);
  if (!parseResult.success || !parseResult.data) {
    return [{
      success: false,
      target,
      error: parseResult.error || 'Failed to parse Sigma rules.',
    }];
  }

  const rules = Array.isArray(parseResult.data) ? parseResult.data : [parseResult.data];
  return rules.map((rule: ParsedSigmaRule) => {
    const ruleYaml = rule.raw;
    return convertSigmaRule(ruleYaml, target);
  });
}
