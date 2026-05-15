
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
        name: 'vt_file_report',
        description: 'Get a VirusTotal report for a file hash (MD5, SHA1, SHA256)',
        inputSchema: {
          type: 'object',
          properties: {
            hash: { type: 'string', description: 'The file hash to lookup' },
          },
          required: ['hash'],
        },
      },
      {
        name: 'vt_url_report',
        description: 'Get a VirusTotal report for a URL',
        inputSchema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'The URL to lookup' },
          },
          required: ['url'],
        },
      },
      {
        name: 'vt_domain_report',
        description: 'Get a VirusTotal report for a domain',
        inputSchema: {
          type: 'object',
          properties: {
            domain: { type: 'string', description: 'The domain to lookup' },
          },
          required: ['domain'],
        },
      },
      {
        name: 'vt_ip_report',
        description: 'Get a VirusTotal report for an IP address',
        inputSchema: {
          type: 'object',
          properties: {
            ip: { type: 'string', description: 'The IP address to lookup' },
          },
          required: ['ip'],
        },
      },
      {
        name: 'shodan_host_info',
        description: 'Get Shodan host information for an IP address',
        inputSchema: {
          type: 'object',
          properties: {
            ip: { type: 'string', description: 'The IP address to lookup' },
          },
          required: ['ip'],
        },
      },
      {
        name: 'shodan_search',
        description: 'Search Shodan for hosts matching a query',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'The Shodan search query' },
          },
          required: ['query'],
        },
      },
      {
        name: 'nvd_cve_details',
        description: 'Get detailed information for a specific CVE ID',
        inputSchema: {
          type: 'object',
          properties: {
            cveId: { type: 'string', description: 'The CVE ID (e.g., CVE-2021-44228)' },
          },
          required: ['cveId'],
        },
      },
      {
        name: 'nvd_search',
        description: 'Search NVD for CVEs. Use daysBack to search for recent CVEs (e.g., daysBack=0 for today, daysBack=7 for past week, daysBack=30 for past month). The server automatically computes the correct dates.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: { type: 'string', description: 'Optional keyword to search for' },
            daysBack: { type: 'number', description: 'Look back N days from today. Use this instead of manual dates. Examples: 0=today, 7=past week, 30=past month, 90=past 3 months' },
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
        name: 'anyrun_task_details',
        description: 'Get details for an AnyRun task',
        inputSchema: {
          type: 'object',
          properties: {
            taskId: { type: 'string', description: 'The AnyRun task ID' },
          },
          required: ['taskId'],
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
        name: 'anyrun_submit_url',
        description: 'Submit a URL to AnyRun for analysis',
        inputSchema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'The URL to analyze' },
          },
          required: ['url'],
        },
      },
      {
        name: 'anyrun_submit_file',
        description: 'Submit a local file to AnyRun for analysis',
        inputSchema: {
          type: 'object',
          properties: {
            filePath: { type: 'string', description: 'The absolute path to the file on disk' },
          },
          required: ['filePath'],
        },
      },
      {
        name: 'anyrun_get_report',
        description: 'Retrieve the final analysis report for a completed AnyRun task',
        inputSchema: {
          type: 'object',
          properties: {
            taskId: { type: 'string', description: 'The AnyRun task ID' },
          },
          required: ['taskId'],
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
        name: 'otx_indicator_pulses',
        description: 'Find all OTX Pulses associated with an indicator',
        inputSchema: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['IPv4', 'IPv6', 'domain', 'file', 'url'], description: 'The type of indicator' },
            value: { type: 'string', description: 'The indicator value' },
          },
          required: ['type', 'value'],
        },
      },
      {
        name: 'otx_pulse_details',
        description: 'Get full details of a specific threat pulse',
        inputSchema: {
          type: 'object',
          properties: {
            pulseId: { type: 'string', description: 'The OTX Pulse ID' },
          },
          required: ['pulseId'],
        },
      },
      {
        name: 'otx_search_pulses',
        description: 'Search for pulses by keyword. When modifiedSince is provided, searches your subscribed feed by date (use get_current_datetime first to get the current date). When omitted, searches globally by relevance.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'The search query (keyword)' },
            modifiedSince: { type: 'string', description: 'Optional ISO 8601 date. Only return pulses modified after this date. Use get_current_datetime tool first to get the current date, then compute the past date (e.g., 3 months ago). Example: "2026-02-15T00:00:00.000Z"' },
            page: { type: 'number', description: 'Page number (default: 1). Only used when modifiedSince is not set.' },
            limit: { type: 'number', description: 'Results per page (default: 25, max: 200 when modifiedSince is set)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'otx_subscribed_pulses',
        description: 'Get your subscribed pulse feed from AlienVault OTX (paginated)',
        inputSchema: {
          type: 'object',
          properties: {
            page: { type: 'number', description: 'Page number (default: 1)' },
            limit: { type: 'number', description: 'Results per page (default: 20)' },
          },
        },
      },
      {
        name: 'otx_recent_activity',
        description: 'Get recent OTX community activity (paginated)',
        inputSchema: {
          type: 'object',
          properties: {
            page: { type: 'number', description: 'Page number (default: 1)' },
            limit: { type: 'number', description: 'Results per page (default: 20)' },
          },
        },
      },
      {
        name: 'get_current_datetime',
        description: 'Get the current date and time in ISO 8601 format. Use this to compute date ranges for other tools (e.g., modifiedSince for otx_search_pulses).',
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
      {
        name: 'github_search_advisories',
        description: 'Search GitHub for security advisories and vulnerability discussions',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'The search query (e.g., "CVE-2021-44228")' },
          },
          required: ['query'],
        },
      },
      {
        name: 'github_search_poc',
        description: 'Search GitHub for exploit PoC code related to a CVE or vulnerability',
        inputSchema: {
          type: 'object',
          properties: {
            cveId: { type: 'string', description: 'The CVE ID to search for (e.g., "CVE-2021-44228")' },
          },
          required: ['cveId'],
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
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case 'vt_file_report':
        return { content: [{ type: 'text', text: JSON.stringify(await vt.getFileReport(args.hash as string)) }] };
      case 'vt_url_report':
        return { content: [{ type: 'text', text: JSON.stringify(await vt.getUrlReport(args.url as string)) }] };
      case 'vt_domain_report':
        return { content: [{ type: 'text', text: JSON.stringify(await vt.getDomainReport(args.domain as string)) }] };
      case 'vt_ip_report':
        return { content: [{ type: 'text', text: JSON.stringify(await vt.getIpReport(args.ip as string)) }] };
      case 'shodan_host_info':
        return { content: [{ type: 'text', text: JSON.stringify(await shodan.getHostInfo(args.ip as string)) }] };
      case 'shodan_search':
        return { content: [{ type: 'text', text: JSON.stringify(await shodan.searchHosts(args.query as string)) }] };
      case 'nvd_cve_details':
        return { content: [{ type: 'text', text: JSON.stringify(await nvd.getCveDetails(args.cveId as string)) }] };
      case 'nvd_search': {
        const keyword = args.keyword as string | undefined;
        const daysBack = args.daysBack as number | undefined;

        // If daysBack is provided, compute date range automatically
        if (daysBack !== undefined) {
          const endDate = new Date();
          const startDate = new Date();
          startDate.setDate(startDate.getDate() - daysBack);
          // When daysBack is 0, use start of today to avoid zero-length range
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
      case 'anyrun_task_details':
        return { content: [{ type: 'text', text: JSON.stringify(await anyrun.getTaskDetails(args.taskId as string)) }] };
      case 'anyrun_search':
        return { content: [{ type: 'text', text: JSON.stringify(await anyrun.searchTasks(args.query as string)) }] };
      case 'anyrun_submit_url':
        return { content: [{ type: 'text', text: JSON.stringify(await anyrun.submitUrl(args.url as string)) }] };
      case 'anyrun_submit_file':
        return { content: [{ type: 'text', text: JSON.stringify(await anyrun.submitFile(args.filePath as string)) }] };
      case 'anyrun_get_report':
        return { content: [{ type: 'text', text: JSON.stringify(await anyrun.getAnalysisReport(args.taskId as string)) }] };
      case 'otx_indicator_details':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getIndicatorDetails(args.type as string, args.value as string, args.section as string | undefined)) }] };
      case 'otx_indicator_pulses':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getIndicatorPulses(args.type as string, args.value as string)) }] };
      case 'otx_pulse_details':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getPulseDetails(args.pulseId as string)) }] };
      case 'otx_search_pulses':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.searchPulses(args.query as string, args.page as number || 1, args.limit as number || 25, args.modifiedSince as string | undefined)) }] };
      case 'otx_subscribed_pulses':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getSubscribedPulses(args.page as number || 1, args.limit as number || 20)) }] };
      case 'otx_recent_activity':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getRecentActivity(args.page as number || 1, args.limit as number || 20)) }] };
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
      case 'github_search_advisories':
        return { content: [{ type: 'text', text: JSON.stringify(await github.searchAdvisories(args.query as string)) }] };
      case 'github_search_poc':
        return { content: [{ type: 'text', text: JSON.stringify(await github.searchExploitPoC(args.cveId as string)) }] };
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
