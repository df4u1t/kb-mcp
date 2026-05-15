import { ParsedSigmaRule } from '../parser.js';

// ---------------------------------------------------------------------------
// QRadar AQL Converter
// ---------------------------------------------------------------------------

/**
 * Map Sigma field names to QRadar AQL field names.
 */
const QRADAR_FIELD_MAP: Record<string, string> = {
  DestinationIp: 'destinationIP',
  SourceIp: 'sourceIP',
  QueryName: 'domainName',
  Url: 'url',
  Hashes: 'fileHash',
  Description: 'description',
  SenderMail: 'sender',
  TargetObject: 'registryKey',
  Mutex: 'mutex',
  CommandLine: 'processName',
  Image: 'processPath',
  ParentImage: 'parentProcessPath',
  User: 'userName',
  ProcessId: 'processId',
};

/**
 * Map Sigma match type modifiers to QRadar AQL operators.
 */
function matchTypeToAql(field: string, value: string, modifier?: string): string {
  switch (modifier) {
    case 'contains':
      return `${field} LIKE '%${escapeAqlValue(value)}%'`;
    case 'startswith':
      return `${field} LIKE '${escapeAqlValue(value)}%'`;
    case 'endswith':
      return `${field} LIKE '%${escapeAqlValue(value)}'`;
    case 'exact':
    default:
      return `${field} = '${escapeAqlValue(value)}'`;
  }
}

/**
 * Escape special characters in AQL string literals.
 */
function escapeAqlValue(value: string): string {
  return value.replace(/'/g, "''");
}

/**
 * Convert a parsed Sigma rule to a QRadar AQL query.
 */
export function convertToQRadar(rule: ParsedSigmaRule): string {
  const parts: string[] = [];

  // SELECT clause
  parts.push('SELECT');

  // Build field list from detection selections
  const fields = new Set<string>();
  for (const selValue of Object.values(rule.detection.selections)) {
    if (typeof selValue === 'object' && selValue !== null) {
      for (const field of Object.keys(selValue as Record<string, any>)) {
        const [actualField] = field.split('|');
        const aqlField = QRADAR_FIELD_MAP[actualField] || actualField;
        fields.add(aqlField);
      }
    }
  }

  if (fields.size > 0) {
    parts.push([...fields].join(', '));
  } else {
    parts.push('*');
  }
  parts.push('FROM events');

  // WHERE clause
  const whereConditions: string[] = [];

  // Add logsource-based category filter
  if (rule.logsource.category) {
    const categoryMap: Record<string, string> = {
      network_connection: 'Network Traffic',
      dns_query: 'DNS',
      proxy: 'Proxy',
      process_creation: 'Process',
      registry_set: 'Registry',
      file_event: 'File Monitoring',
      email: 'Email',
      application: 'Application',
    };
    const category = categoryMap[rule.logsource.category];
    if (category) {
      whereConditions.push(`category = '${category}'`);
    }
  }

  // Convert detection selections to AQL
  const selectionConditions: string[] = [];
  for (const [selName, selValue] of Object.entries(rule.detection.selections)) {
    if (typeof selValue === 'object' && selValue !== null) {
      const fieldConditions: string[] = [];
      for (const [field, value] of Object.entries(selValue as Record<string, any>)) {
        if (typeof value === 'string') {
          const [actualField, modifier] = field.split('|');
          const aqlField = QRADAR_FIELD_MAP[actualField] || actualField;
          fieldConditions.push(matchTypeToAql(aqlField, value, modifier));
        } else if (Array.isArray(value)) {
          const [actualField, modifier] = field.split('|');
          const aqlField = QRADAR_FIELD_MAP[actualField] || actualField;
          const orParts = value.map((v: string) => matchTypeToAql(aqlField, v, modifier));
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
      whereConditions.push(`(${selectionConditions.join(' OR ')})`);
    } else if (condition.includes(' and ') || condition.includes(' not ')) {
      const conditionExpr = condition.replace(/selection(\d+)/g, (_, num) => {
        return selectionConditions[parseInt(num)] || `selection${num}`;
      });
      whereConditions.push(conditionExpr);
    } else {
      whereConditions.push(selectionConditions.join(' AND '));
    }
  }

  if (whereConditions.length > 0) {
    parts.push(`WHERE ${whereConditions.join(' AND ')}`);
  }

  // Add LIMIT
  parts.push('LIMIT 100');

  // Add severity-based filtering for high/critical rules
  if (rule.level && ['high', 'critical'].includes(rule.level)) {
    parts.push('LAST 24 HOURS');
  }

  return parts.join('\n');
}

/**
 * Convert a parsed Sigma rule to a QRadar rule/offense definition.
 */
export function convertToQRadarRule(rule: ParsedSigmaRule): string {
  const aql = convertToQRadar(rule);
  const lines: string[] = [];

  lines.push(`<!-- Sigma Rule: ${rule.title} -->`);
  lines.push(`<!-- ID: ${rule.id} -->`);
  if (rule.description) lines.push(`<!-- Description: ${rule.description} -->`);
  if (rule.level) lines.push(`<!-- Severity: ${rule.level} -->`);
  lines.push('');
  lines.push('<rule name="' + rule.title.replace(/"/g, '&quot;') + '">');
  lines.push('  <enabled>true</enabled>');
  lines.push('  <severity>' + (rule.level === 'critical' ? '10' : rule.level === 'high' ? '7' : '5') + '</severity>');
  lines.push('  <description>' + (rule.description || rule.title).replace(/"/g, '&quot;') + '</description>');
  lines.push('  <notes></notes>');
  lines.push('  <tests>');
  lines.push('    <test>');
  lines.push('      <condition>when the event matches the following AQL</condition>');
  lines.push('      <aql>' + aql.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</aql>');
  lines.push('    </test>');
  lines.push('  </tests>');
  lines.push('  <responses>');
  lines.push('    <response>');
  lines.push('      <type>createOffense</type>');
  lines.push('    </response>');
  lines.push('  </responses>');
  lines.push('</rule>');

  return lines.join('\n');
}
