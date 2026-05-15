import axios from 'axios';
import { config } from '../config.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SigmaHQRule {
  title: string;
  id: string;
  description?: string;
  level?: string;
  status?: string;
  tags?: string[];
  logsource?: {
    category?: string;
    product?: string;
    service?: string;
  };
  filePath?: string;
  repoUrl?: string;
  raw?: string;
}

export interface SigmaHQSearchResult {
  success: boolean;
  data?: SigmaHQRule[];
  error?: string;
  totalCount: number;
  source: 'github_api' | 'github_code_search';
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SIGMA_HQ_OWNER = 'SigmaHQ';
const SIGMA_HQ_REPO = 'sigma';
const SIGMA_HQ_BASE_URL = `https://api.github.com/repos/${SIGMA_HQ_OWNER}/${SIGMA_HQ_REPO}`;
const SIGMA_HQ_RAW_BASE = `https://raw.githubusercontent.com/${SIGMA_HQ_OWNER}/${SIGMA_HQ_REPO}/master`;

/**
 * Map Sigma HQ category paths to logsource categories.
 */
const CATEGORY_PATHS: Record<string, { category: string; product: string; service?: string }> = {
  'process_creation': { category: 'process_creation', product: 'windows' },
  'registry_set': { category: 'registry_set', product: 'windows' },
  'registry_event': { category: 'registry_set', product: 'windows' },
  'file_event': { category: 'file_event', product: 'windows' },
  'file_change': { category: 'file_event', product: 'windows' },
  'network_connection': { category: 'network_connection', product: 'windows' },
  'dns_query': { category: 'dns_query', product: 'windows' },
  'proxy': { category: 'proxy', product: 'windows' },
  'windows_built_in': { category: 'process_creation', product: 'windows', service: 'security' },
  'powershell': { category: 'process_creation', product: 'windows', service: 'powershell' },
  'security_alert': { category: 'process_creation', product: 'windows', service: 'security' },
  'created_remote_thread': { category: 'process_creation', product: 'windows' },
  'image_load': { category: 'image_load', product: 'windows' },
  'pipe_created': { category: 'pipe_created', product: 'windows' },
  'wmi_event': { category: 'wmi_event', product: 'windows' },
  'windows_sysmon': { category: 'process_creation', product: 'windows', service: 'sysmon' },
};

// ---------------------------------------------------------------------------
// GitHub API helpers
// ---------------------------------------------------------------------------

/**
 * Get a GitHub API token from config or environment.
 */
function getGitHubToken(): string | undefined {
  return (config as any)?.GITHUB_TOKEN || process.env.GITHUB_TOKEN;
}

/**
 * Create authenticated GitHub API headers.
 */
function getGitHubHeaders(): Record<string, string> {
  const token = getGitHubToken();
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'kb-mcp-security-server',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Search Functions
// ---------------------------------------------------------------------------

/**
 * Search the Sigma HQ repository for rules matching a query.
 * Uses GitHub's code search API to find relevant rule files.
 */
export async function searchSigmaHQ(query: string, maxResults: number = 20): Promise<SigmaHQSearchResult> {
  try {
    // Search for rule files containing the query
    const searchQuery = `repo:${SIGMA_HQ_OWNER}/${SIGMA_HQ_REPO} path:rules/${query} language:yaml`;
    const response = await axios.get('https://api.github.com/search/code', {
      headers: getGitHubHeaders(),
      params: {
        q: searchQuery,
        per_page: Math.min(maxResults, 100),
      },
    });

    const items = response.data?.items || [];
    if (items.length === 0) {
      // Fallback: try a broader text search
      return await searchSigmaHQByContent(query, maxResults);
    }

    const rules: SigmaHQRule[] = [];
    for (const item of items.slice(0, maxResults)) {
      try {
        const rawResponse = await axios.get(item.download_url, {
          headers: { 'User-Agent': 'kb-mcp-security-server' },
          timeout: 10000,
        });
        const yamlContent = typeof rawResponse.data === 'string' ? rawResponse.data : JSON.stringify(rawResponse.data);

        // Extract basic metadata from the YAML
        const title = extractYamlField(yamlContent, 'title');
        const id = extractYamlField(yamlContent, 'id');
        const description = extractYamlField(yamlContent, 'description');
        const level = extractYamlField(yamlContent, 'level');
        const status = extractYamlField(yamlContent, 'status');

        rules.push({
          title: title || item.name.replace(/\.(yml|yaml)$/, ''),
          id: id || '',
          description,
          level,
          status,
          filePath: item.path,
          repoUrl: item.html_url,
          raw: yamlContent.substring(0, 2000), // Truncate to avoid huge responses
        });
      } catch {
        // Skip files that fail to fetch
        rules.push({
          title: item.name.replace(/\.(yml|yaml)$/, ''),
          id: '',
          filePath: item.path,
          repoUrl: item.html_url,
        });
      }
    }

    return {
      success: true,
      data: rules,
      totalCount: response.data?.total_count || rules.length,
      source: 'github_api',
    };
  } catch (error: any) {
    // Fallback to content search
    return await searchSigmaHQByContent(query, maxResults);
  }
}

/**
 * Fallback search: search Sigma HQ rules by content/keyword.
 * Uses GitHub's code search with a broader query.
 */
async function searchSigmaHQByContent(query: string, maxResults: number = 20): Promise<SigmaHQSearchResult> {
  try {
    const searchQuery = `repo:${SIGMA_HQ_OWNER}/${SIGMA_HQ_REPO} path:rules/ ${query}`;
    const response = await axios.get('https://api.github.com/search/code', {
      headers: getGitHubHeaders(),
      params: {
        q: searchQuery,
        per_page: Math.min(maxResults, 100),
      },
    });

    const items = response.data?.items || [];
    const rules: SigmaHQRule[] = [];

    for (const item of items.slice(0, maxResults)) {
      try {
        const rawResponse = await axios.get(item.download_url, {
          headers: { 'User-Agent': 'kb-mcp-security-server' },
          timeout: 10000,
        });
        const yamlContent = typeof rawResponse.data === 'string' ? rawResponse.data : JSON.stringify(rawResponse.data);
        const title = extractYamlField(yamlContent, 'title');
        const id = extractYamlField(yamlContent, 'id');

        rules.push({
          title: title || item.name.replace(/\.(yml|yaml)$/, ''),
          id: id || '',
          filePath: item.path,
          repoUrl: item.html_url,
          raw: yamlContent.substring(0, 2000),
        });
      } catch {
        rules.push({
          title: item.name.replace(/\.(yml|yaml)$/, ''),
          id: '',
          filePath: item.path,
          repoUrl: item.html_url,
        });
      }
    }

    return {
      success: true,
      data: rules,
      totalCount: response.data?.total_count || rules.length,
      source: 'github_code_search',
    };
  } catch (error: any) {
    return {
      success: false,
      error: `Failed to search Sigma HQ: ${error.message}`,
      totalCount: 0,
      source: 'github_code_search',
    };
  }
}

/**
 * Search Sigma HQ for rules related to a specific CVE.
 */
export async function searchSigmaHQByCVE(cveId: string, maxResults: number = 10): Promise<SigmaHQSearchResult> {
  return searchSigmaHQByContent(cveId, maxResults);
}

/**
 * Search Sigma HQ for rules related to a specific MITRE ATT&CK technique.
 */
export async function searchSigmaHQByTechnique(techniqueId: string, maxResults: number = 10): Promise<SigmaHQSearchResult> {
  const searchTerms = techniqueId.replace('attack.', '');
  return searchSigmaHQByContent(searchTerms, maxResults);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract a top-level field from a YAML string using regex.
 * Simple parser that handles quoted and unquoted values.
 */
function extractYamlField(yaml: string, field: string): string | undefined {
  const regex = new RegExp(`^${field}:\\s+['\"](.+)['\"]`, 'm');
  const match = yaml.match(regex);
  if (match) return match[1];

  const unquotedRegex = new RegExp(`^${field}:\\s+(.+)`, 'm');
  const unquotedMatch = yaml.match(unquotedRegex);
  if (unquotedMatch) {
    const val = unquotedMatch[1].trim();
    // Only return if it looks like a simple value (not a list or object)
    if (!val.startsWith('[') && !val.startsWith('{')) {
      return val;
    }
  }

  return undefined;
}
