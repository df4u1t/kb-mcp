
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

const vt = new VirusTotalProvider();
const shodan = new ShodanProvider();
const nvd = new NVDProvider();
const anyrun = new AnyRunProvider();
const otx = new AlienVaultOTXProvider();
const github = new GitHubProvider();

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
        description: 'Search NVD for CVEs matching a keyword',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: { type: 'string', description: 'The keyword to search for' },
          },
          required: ['keyword'],
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
        name: 'otx_indicator_info',
        description: 'Get general information and reputation for an indicator from AlienVault OTX',
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
        description: 'Search for pulses by keyword',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'The search query' },
          },
          required: ['query'],
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
      case 'nvd_search':
        return { content: [{ type: 'text', text: JSON.stringify(await nvd.searchCves(args.keyword as string)) }] };
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
      case 'otx_indicator_info':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getIndicatorGeneral(args.type as string, args.value as string)) }] };
      case 'otx_indicator_pulses':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getIndicatorPulses(args.type as string, args.value as string)) }] };
      case 'otx_pulse_details':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.getPulseDetails(args.pulseId as string)) }] };
      case 'otx_search_pulses':
        return { content: [{ type: 'text', text: JSON.stringify(await otx.searchPulses(args.query as string)) }] };
      case 'github_search_advisories':
        return { content: [{ type: 'text', text: JSON.stringify(await github.searchAdvisories(args.query as string)) }] };
      case 'github_search_poc':
        return { content: [{ type: 'text', text: JSON.stringify(await github.searchExploitPoC(args.cveId as string)) }] };
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
