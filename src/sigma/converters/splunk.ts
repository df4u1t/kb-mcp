import { ParsedSigmaRule } from '../parser.js';

// ---------------------------------------------------------------------------
// Splunk SPL Converter
// ---------------------------------------------------------------------------

/**
 * Map Sigma field names to Splunk field names.
 */
const SPLUNK_FIELD_MAP: Record<string, string> = {
  DestinationIp: 'dest_ip',
  SourceIp: 'src_ip',
  QueryName: 'query',
  Url: 'url',
  Hashes: 'file_hash',
  Description: 'signature',
  SenderMail: 'from_email',
  TargetObject: 'registry_path',
  Mutex: 'mutex',
  CommandLine: 'process',
  Image: 'process_path',
  ParentImage: 'parent_process',
  User: 'user',
  ProcessId: 'process_id',
};

/**
 * Map Sigma match type modifiers to Splunk search operators.
 */
function matchTypeToSplunk(field: string, value: string, modifier?: string): string {
  switch (modifier) {
    case 'contains':
      return `${field}=*${escapeSplunkValue(value)}*`;
    case 'startswith':
      return `${field}=${escapeSplunkValue(value)}*`;
    case 'endswith':
      return `${field}=*${escapeSplunkValue(value)}`;
    case 'exact':
    default:
      return `${field}=${escapeSplunkValue(value)}`;
  }
}

/**
 * Escape special Splunk characters in a value.
 */
function escapeSplunkValue(value: string): string {
  // Wrap in quotes if contains spaces or special chars
  if (/[\s*\\"()\[\]{}|&!]/.test(value)) {
    return `"${value.replace(/"/g, '\\"')}"`;
  }
  return value;
}

/**
 * Convert a parsed Sigma rule to Splunk SPL query.
 */
export function convertToSplunk(rule: ParsedSigmaRule): string {
  const parts: string[] = [];
  const index = rule.logsource.product === 'windows' ? 'index=windows' : 'index=*';

  // Base search
  parts.push(index);

  // Add logsource filters
  if (rule.logsource.category) {
    parts.push(`sourcetype=${rule.logsource.category}`);
  }

  // Convert detection selections to SPL
  const selectionConditions: string[] = [];
  for (const [selName, selValue] of Object.entries(rule.detection.selections)) {
    if (typeof selValue === 'object' && selValue !== null) {
      const fieldConditions: string[] = [];
      for (const [field, value] of Object.entries(selValue as Record<string, any>)) {
        if (typeof value === 'string') {
          const [actualField, modifier] = field.split('|');
          const splunkField = SPLUNK_FIELD_MAP[actualField] || actualField.toLowerCase();
          fieldConditions.push(matchTypeToSplunk(splunkField, value, modifier));
        } else if (Array.isArray(value)) {
          // List of values — use OR
          const [actualField, modifier] = field.split('|');
          const splunkField = SPLUNK_FIELD_MAP[actualField] || actualField.toLowerCase();
          const orParts = value.map((v: string) => matchTypeToSplunk(splunkField, v, modifier));
          fieldConditions.push(`(${orParts.join(' OR ')})`);
        }
      }
      if (fieldConditions.length > 0) {
        selectionConditions.push(`(${fieldConditions.join(' AND ')})`);
      }
    }
  }

  // Apply condition logic
  const condition = rule.detection.condition;
  if (selectionConditions.length > 0) {
    if (condition.startsWith('1 of')) {
      // OR logic
      parts.push(`(${selectionConditions.join(' OR ')})`);
    } else if (condition.includes(' and ') || condition.includes(' not ')) {
      // Complex condition — use as-is with numbered selections
      const conditionExpr = condition.replace(/selection(\d+)/g, (_, num) => {
        return selectionConditions[parseInt(num)] || `selection${num}`;
      });
      parts.push(conditionExpr);
    } else {
      // AND logic or single selection
      parts.push(selectionConditions.join(' AND '));
    }
  }

  // Add tags as search modifiers
  if (rule.tags && rule.tags.length > 0) {
    const mitreTags = rule.tags.filter(t => t.startsWith('attack.'));
    if (mitreTags.length > 0) {
      parts.push(`| eval mitre_techniques="${mitreTags.join(',')}"`);
    }
  }

  // Add level-based alerting
  if (rule.level && ['high', 'critical'].includes(rule.level)) {
    parts.push('| eval severity="high"');
  }

  return parts.join(' ');
}

/**
 * Convert a parsed Sigma rule to a Splunk saved search / alert definition.
 */
export function convertToSplunkAlert(rule: ParsedSigmaRule): string {
  const search = convertToSplunk(rule);
  const lines: string[] = [];

  lines.push(`# Sigma Rule: ${rule.title}`);
  lines.push(`# ID: ${rule.id}`);
  if (rule.description) lines.push(`# Description: ${rule.description}`);
  if (rule.level) lines.push(`# Severity: ${rule.level}`);
  lines.push('');
  lines.push(`[${rule.title.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase()}]`);
  lines.push(`search = ${search}`);
  lines.push('cron_schedule = */60 * * * *');
  lines.push('description = ' + (rule.description || rule.title));
  lines.push('disabled = 0');
  lines.push('enableSched = 1');
  lines.push('alert.severity = ' + (rule.level === 'critical' ? '6' : rule.level === 'high' ? '5' : '3'));
  lines.push('alert.suppress = 0');
  lines.push('alert.track = 1');

  return lines.join('\n');
}
