
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { VirusTotalProvider } from './providers/virustotal.js';
import { ShodanProvider } from './providers/shodan.js';
import { NVDProvider } from './providers/nvd.js';
import { AnyRunProvider } from './providers/anyrun.js';
import { AlienVaultOTXProvider } from './providers/alienvault.js';
import { GitHubProvider } from './providers/github.js';
import { SigmaRuleGenerator } from './providers/sigma.js';
import axios from 'axios';

const vt = new VirusTotalProvider();
const shodan = new ShodanProvider();
const nvd = new NVDProvider();
const anyrun = new AnyRunProvider();
const otx = new AlienVaultOTXProvider();
const github = new GitHubProvider();
const sigma = new SigmaRuleGenerator();

const server = new Server(
  {
    name: 'security-intelligence-server',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'vt_lookup',
        description: 'Look up a file hash, URL, domain, or IP address on VirusTotal',
        inputSchema: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['file', 'url', 'domain', 'ip'], description: 'Type of indicator to look up' },
            value: { type: 'string', description: 'The indicator value (hash, URL, domain, or IP)' },
          },
          required: ['type', 'value'],
        },
      },
      {
        name: 'shodan_query',
        description: 'Query Shodan for host information by IP or search for hosts matching a query',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['host_info', 'search'], description: '"host_info" for IP lookup, "search" for keyword search' },
            value: { type: 'string', description: 'IP address (for host_info) or search query (for search)' },
          },
          required: ['action', 'value'],
        },
      },
      {
        name: 'nvd_query',
        description: 'Query the NVD for CVE details by ID, or search CVEs by keyword/date/severity. Use daysBack for recent CVEs (e.g., daysBack=0 for today, 7 for past week, 30 for past month).',
        inputSchema: {
          type: 'object',
          properties: {
            cveId: { type: 'string', description: 'Specific CVE ID to fetch details for (e.g., CVE-2021-44228). When provided, other search params are ignored.' },
            keyword: { type: 'string', description: 'Optional keyword to search for' },
            daysBack: { type: 'number', description: 'Look back N days from today. Examples: 0=today, 7=past week, 30=past month, 90=past 3 months' },
            pubStartDate: { type: 'string', description: 'Optional explicit published start date (ISO 8601). Only use if daysBack is not sufficient.' },
            pubEndDate: { type: 'string', description: 'Optional explicit published end date (ISO 8601)' },
            lastModStartDate: { type: 'string', description: 'Filter by last modified start date (ISO 8601)' },
            lastModEndDate: { type: 'string', description: 'Filter by last modified end date (ISO 8601)' },
            cvssV3Severity: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], description: 'Filter by CVSS v3 severity rating' },
            resultsPerPage: { type: 'number', description: 'Results per page (max 200)' },
            startIndex: { type: 'number', description: 'Start index for pagination' },
          },
        },
      },
      {
        name: 'anyrun_task',
        description: 'Get details or analysis report for an AnyRun task by task ID',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['details', 'report'], description: '"details" for task info, "report" for full analysis report' },
            taskId: { type: 'string', description: 'The AnyRun task ID' },
          },
          required: ['action', 'taskId'],
        },
      },
      {
        name: 'anyrun_submit',
        description: 'Submit a URL or local file to AnyRun for sandbox analysis',
        inputSchema: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['url', 'file'], description: 'Type of submission' },
            value: { type: 'string', description: 'The URL to analyze or absolute path to the file on disk' },
          },
          required: ['type', 'value'],
        },
      },
      {
        name: 'anyrun_search',
        description: 'Search AnyRun for tasks matching a query',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'The search query' },
          },
          required: ['query'],
        },
      },
      {
        name: 'otx_indicator_details',
        description: 'Get detailed information for an indicator from AlienVault OTX. Returns all available sections (reputation, geo, malware, url_list, passive_dns, analysis) or a specific section if requested.',
        inputSchema: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['IPv4', 'IPv6', 'domain', 'hostname', 'file', 'url'], description: 'The type of indicator' },
            value: { type: 'string', description: 'The indicator value' },
            section: { type: 'string', enum: ['general', 'reputation', 'geo', 'malware', 'url_list', 'passive_dns', 'analysis'], description: 'Optional specific section to fetch. If omitted, all available sections are returned.' },
          },
          required: ['type', 'value'],
        },
      },
      {
        name: 'otx_query',
        description: 'Query AlienVault OTX for pulses, activity, or indicator associations',
        inputSchema: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['indicator_pulses', 'pulse_details', 'search_pulses', 'subscribed_pulses', 'recent_activity'], description: 'What to query' },
            indicator_type: { type: 'string', enum: ['IPv4', 'IPv6', 'domain', 'file', 'url'], description: 'Indicator type (required for indicator_pulses)' },
            value: { type: 'string', description: 'Indicator value (required for indicator_pulses)' },
            pulseId: { type: 'string', description: 'Pulse ID (required for pulse_details)' },
            query: { type: 'string', description: 'Search keyword (required for search_pulses)' },
            modifiedSince: { type: 'string', description: 'ISO 8601 date filter (for search_pulses with date scope)' },
            page: { type: 'number', description: 'Page number (default: 1)' },
            limit: { type: 'number', description: 'Results per page (default: 25)' },
          },
          required: ['action'],
        },
      },
      {
        name: 'github_search',
        description: 'Search GitHub for security advisories or exploit PoC code related to a CVE or vulnerability',
        inputSchema: {
          type: 'object',
          properties: {
            search_type: { type: 'string', enum: ['advisories', 'poc'], description: '"advisories" for security advisories, "poc" for exploit proof-of-concept code' },
            query: { type: 'string', description: 'Search query (e.g., "CVE-2021-44228" or a vulnerability name)' },
          },
          required: ['search_type', 'query'],
        },
      },
      {
        name: 'generate_sigma_rules',
        description: 'Generate Sigma detection rules (YAML) from threat indicators such as IPs, domains, URLs, file hashes, or CVEs',
        inputSchema: {
          type: 'object',
          properties: {
            indicators: {
              type: 'string',
              description: 'JSON string of threat indicators array. Each object: { "type": "ip|domain|url|hash|cve", "value": "...", "description?": "...", "references?": ["..."], "tags?": ["..."] }',
            },
            level: { type: 'string', enum: ['informational', 'low', 'medium', 'high', 'critical'], description: 'Severity level (default: high)' },
            status: { type: 'string', enum: ['stable', 'test', 'experimental'], description: 'Rule status (default: test)' },
            author: { type: 'string', description: 'Rule author name' },
            outputFormat: { type: 'string', enum: ['single', 'separate'], description: '"single" combines all indicators into one rule, "separate" creates one rule per indicator (default: separate)' },
          },
          required: ['indicators'],
        },
      },
      {
        name: 'get_current_datetime',
        description: 'Get the current date and time in ISO 8601 format',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'fetch_url',
        description: 'Fetch the content of a web page or API endpoint. Useful for retrieving threat reports, security advisories, or any web-based intelligence.',
        inputSchema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'The URL to fetch' },
          },
          required: ['url'],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case 'vt_lookup': {
        const type = args.type as string;
        const value = args.value as string;
        switch (type) {
          case 'file': return { content: [{ type: 'text', text: JSON.stringify(await vt.getFileReport(value)) }] };
          case 'url': return { content: [{ type: 'text', text: JSON.stringify(await vt.getUrlReport(value)) }] };
          case 'domain': return { content: [{ type: 'text', text: JSON.stringify(await vt.getDomainReport(value)) }] };
          case 'ip': return { content: [{ type: 'text', text: JSON.stringify(await vt.getIpReport(value)) }] };
          default: throw new Error(`Unknown VT lookup type: ${type}`);
        }
      }
      case 'shodan_query': {
        const shodanAction = args.action as string;
        const shodanValue = args.value as string;
        switch (shodanAction) {
          case 'host_info': return { content: [{ type: 'text', text: JSON.stringify(await shodan.getHostInfo(shodanValue)) }] };
          case 'search': return { content: [{ type: 'text', text: JSON.stringify(await shodan.searchHosts(shodanValue)) }] };
          default: throw new Error(`Unknown Shodan action: ${shodanAction}`);
        }
      }
      case 'nvd_query': {
        const cveId = args.cveId as string | undefined;
        // If cveId is provided, fetch single CVE details
        if (cveId) {
          return { content: [{ type: 'text', text: JSON.stringify(await nvd.getCveDetails(cveId)) }] };
        }
        // Otherwise, search with optional filters
        const keyword = args.keyword as string | undefined;
        const daysBack = args.daysBack as number | undefined;

        if (daysBack !== undefined) {
          const endDate = new Date();
          const startDate = new Date();
          startDate.setDate(startDate.getDate() - daysBack);
          if (daysBack === 0) {
            startDate.setHours(0, 0, 0, 0);
          }
          return { content: [{ type: 'text', text: JSON.stringify(await nvd.searchCves({
            keyword,
            pubStartDate: startDate.toISOString(),
            pubEndDate: endDate.toISOString(),
            cvssV3Severity: args.cvssV3Severity as string | undefined,
            resultsPerPage: args.resultsPerPage as number | undefined,
            startIndex: args.startIndex as number | undefined,
          })) }] };
        }

        return { content: [{ type: 'text', text: JSON.stringify(await nvd.searchCves({
          keyword,
          pubStartDate: args.pubStartDate as string | undefined,
          pubEndDate: args.pubEndDate as string | undefined,
          lastModStartDate: args.lastModStartDate as string | undefined,
          lastModEndDate: args.lastModEndDate as string | undefined,
          cvssV3Severity: args.cvssV3Severity as string | undefined,
          resultsPerPage: args.resultsPerPage as number | undefined,
          startIndex: args.startIndex as number | undefined,
        })) }] };
      }
      case 'anyrun_task': {
        const taskAction = args.action as string;
        const taskId = args.taskId as string;
        switch (taskAction) {
          case 'details': return { content: [{ type: 'text', text: JSON.stringify(await anyrun.getTaskDetails(taskId)) }] };
          case 'report': return { content: [{ type: 'text', text: JSON.stringify(await anyrun.getAnalysisReport(taskId)) }] };
          default: throw new Error(`Unknown AnyRun task action: ${taskAction}`);
        }
      }
      case 'anyrun_submit': {
        const submitType = args.type as string;
        const submitValue = args.value as string;
        switch (submitType) {
          case 'url': return { content: [{ type: 'text', text: JSON.stringify(await anyrun.submitUrl(submitValue)) }] };
          case 'file': return { content: [{ type: 'text', text: JSON.stringify(await anyrun.submitFile(submitValue)) }] };
          default: throw new Error(`Unknown AnyRun submit type: ${submitType}`);
        }
      }
      case 'anyrun_search':
        return { content: [{ type: 'text', text: JSON.stringify(await anyrun.searchTasks(args.query as string)) }] };
      case 'otx_indicator_details':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getIndicatorDetails(args.type as string, args.value as string, args.section as string | undefined)) }] };
      case 'otx_query': {
        const otxAction = args.action as string;
        switch (otxAction) {
          case 'indicator_pulses':
            return { content: [{ type: 'text', text: JSON.stringify(await otx.getIndicatorPulses(args.indicator_type as string, args.value as string)) }] };
          case 'pulse_details':
            return { content: [{ type: 'text', text: JSON.stringify(await otx.getPulseDetails(args.pulseId as string)) }] };
          case 'search_pulses':
            return { content: [{ type: 'text', text: JSON.stringify(await otx.searchPulses(args.query as string, args.page as number || 1, args.limit as number || 25, args.modifiedSince as string | undefined)) }] };
          case 'subscribed_pulses':
            return { content: [{ type: 'text', text: JSON.stringify(await otx.getSubscribedPulses(args.page as number || 1, args.limit as number || 20)) }] };
          case 'recent_activity':
            return { content: [{ type: 'text', text: JSON.stringify(await otx.getRecentActivity(args.page as number || 1, args.limit as number || 20)) }] };
          default:
            throw new Error(`Unknown OTX action: ${otxAction}`);
        }
      }
      case 'github_search': {
        const ghType = args.search_type as string;
        const ghQuery = args.query as string;
        switch (ghType) {
          case 'advisories': return { content: [{ type: 'text', text: JSON.stringify(await github.searchAdvisories(ghQuery)) }] };
          case 'poc': return { content: [{ type: 'text', text: JSON.stringify(await github.searchExploitPoC(ghQuery)) }] };
          default: throw new Error(`Unknown GitHub search type: ${ghType}`);
        }
      }
      case 'get_current_datetime':
        return { content: [{ type: 'text', text: JSON.stringify({
          provider: 'System',
          data: {
            iso8601: new Date().toISOString(),
            date: new Date().toISOString().split('T')[0],
            unixTimestamp: Date.now(),
          },
          status: 'success',
        }) }] };
      case 'fetch_url': {
        const response = await axios.get(args.url as string, {
          timeout: 15000,
          headers: { 'User-Agent': 'kb-mcp-security-server/1.0' },
          validateStatus: () => true,
        });
        return { content: [{ type: 'text', text: JSON.stringify({
          provider: 'Web',
          data: { url: args.url, status: response.status, content: typeof response.data === 'string' ? response.data : JSON.stringify(response.data) },
          status: 'success',
        }) }] };
      }
      case 'generate_sigma_rules': {
        const indicators = JSON.parse(args.indicators as string);
        const result = sigma.generateFromIndicators(indicators, {
          level: args.level as any,
          status: args.status as any,
          author: args.author as string | undefined,
          outputFormat: args.outputFormat as any,
        });
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }
      default:
        throw new Error(`Tool not found: ${name}`);
    }
  } catch (error: any) {
    return {
      content: [{ type: 'text', text: `Error executing tool ${name}: ${error.message}` }],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Security Intelligence MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Error starting server:', error);
  process.exit(1);
});
