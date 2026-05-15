import { ParsedSigmaRule } from '../parser.js';

// ---------------------------------------------------------------------------
// Elastic EQL / KQL Converter
// ---------------------------------------------------------------------------

/**
 * Map Sigma field names to Elastic EQL field names.
 */
const ELASTIC_FIELD_MAP: Record<string, string> = {
  DestinationIp: 'destination.ip',
  SourceIp: 'source.ip',
  QueryName: 'dns.question.name',
  Url: 'url.full',
  Hashes: 'file.hash.sha256',
  Description: 'rule.description',
  SenderMail: 'email.from.address',
  TargetObject: 'registry.path',
  Mutex: 'process.mutex',
  CommandLine: 'process.command_line',
  Image: 'process.executable',
  ParentImage: 'process.parent.executable',
  User: 'user.name',
  ProcessId: 'process.pid',
};

/**
 * Map Sigma match type modifiers to Elastic query operators.
 */
function matchTypeToElastic(field: string, value: string, modifier?: string): string {
  switch (modifier) {
    case 'contains':
      return `${field}: *${escapeElasticValue(value)}*`;
    case 'startswith':
      return `${field}: ${escapeElasticValue(value)}*`;
    case 'endswith':
      return `${field}: *${escapeElasticValue(value)}`;
    case 'exact':
    default:
      return `${field}: ${escapeElasticValue(value)}`;
  }
}

/**
 * Escape special Elasticsearch characters in a value.
 */
function escapeElasticValue(value: string): string {
  if (/[\s*\\"()\[\]{}|&!+\-~^:]/.test(value)) {
    return `"${value.replace(/"/g, '\\"')}"`;
  }
  return value;
}

/**
 * Convert a parsed Sigma rule to an Elastic EQL query.
 */
export function convertToElasticEQL(rule: ParsedSigmaRule): string {
  const parts: string[] = [];

  // Add event category based on logsource
  if (rule.logsource.category) {
    const categoryMap: Record<string, string> = {
      network_connection: 'network',
      dns_query: 'network',
      proxy: 'network',
      process_creation: 'process',
      registry_set: 'registry',
      file_event: 'file',
      email: 'email',
      application: 'application',
    };
    const eventCategory = categoryMap[rule.logsource.category] || rule.logsource.category;
    parts.push(`event.category : "${eventCategory}"`);
  }

  // Convert detection selections to EQL
  const selectionConditions: string[] = [];
  for (const [selName, selValue] of Object.entries(rule.detection.selections)) {
    if (typeof selValue === 'object' && selValue !== null) {
      const fieldConditions: string[] = [];
      for (const [field, value] of Object.entries(selValue as Record<string, any>)) {
        if (typeof value === 'string') {
          const [actualField, modifier] = field.split('|');
          const esField = ELASTIC_FIELD_MAP[actualField] || actualField.toLowerCase().replace(/([A-Z])/g, '.$1').toLowerCase();
          fieldConditions.push(matchTypeToElastic(esField, value, modifier));
        } else if (Array.isArray(value)) {
          const [actualField, modifier] = field.split('|');
          const esField = ELASTIC_FIELD_MAP[actualField] || actualField.toLowerCase().replace(/([A-Z])/g, '.$1').toLowerCase();
          const orParts = value.map((v: string) => matchTypeToElastic(esField, v, modifier));
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
      parts.push(`(${selectionConditions.join(' OR ')})`);
    } else if (condition.includes(' and ') || condition.includes(' not ')) {
      const conditionExpr = condition.replace(/selection(\d+)/g, (_, num) => {
        return selectionConditions[parseInt(num)] || `selection${num}`;
      });
      parts.push(conditionExpr);
    } else {
      parts.push(selectionConditions.join(' AND '));
    }
  }

  return parts.join(' AND ');
}

/**
 * Convert a parsed Sigma rule to an Elasticsearch query DSL.
 */
export function convertToElasticDSL(rule: ParsedSigmaRule): object {
  const must: object[] = [];
  const should: object[] = [];

  // Add logsource filter
  if (rule.logsource.category) {
    must.push({ term: { 'event.category': rule.logsource.category } });
  }
  if (rule.logsource.product) {
    must.push({ term: { 'event.module': rule.logsource.product } });
  }

  // Convert detection selections
  for (const [selName, selValue] of Object.entries(rule.detection.selections)) {
    if (typeof selValue === 'object' && selValue !== null) {
      const fieldClauses: object[] = [];
      for (const [field, value] of Object.entries(selValue as Record<string, any>)) {
        if (typeof value === 'string') {
          const [actualField, modifier] = field.split('|');
          const esField = ELASTIC_FIELD_MAP[actualField] || actualField.toLowerCase().replace(/([A-Z])/g, '.$1').toLowerCase();

          switch (modifier) {
            case 'contains':
              fieldClauses.push({ wildcard: { [esField]: { value: `*${value}*` } } });
              break;
            case 'startswith':
              fieldClauses.push({ prefix: { [esField]: { value } } });
              break;
            case 'endswith':
              fieldClauses.push({ wildcard: { [esField]: { value: `*${value}` } } });
              break;
            default:
              fieldClauses.push({ term: { [esField]: { value } } });
          }
        } else if (Array.isArray(value)) {
          const [actualField] = field.split('|');
          const esField = ELASTIC_FIELD_MAP[actualField] || actualField.toLowerCase().replace(/([A-Z])/g, '.$1').toLowerCase();
          fieldClauses.push({ terms: { [esField]: value } });
        }
      }
      if (fieldClauses.length > 0) {
        should.push({ bool: { filter: fieldClauses } });
      }
    }
  }

  const query: any = { bool: {} };

  const condition = rule.detection.condition;
  if (condition.startsWith('1 of')) {
    // OR logic
    query.bool.should = should;
    query.bool.minimum_should_match = 1;
    if (must.length > 0) query.bool.filter = must;
  } else {
    // AND logic
    query.bool.filter = [...must, ...should];
  }

  return query;
}
