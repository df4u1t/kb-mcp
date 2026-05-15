import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import { VirusTotalProvider } from './providers/virustotal.js';
import { ShodanProvider } from './providers/shodan.js';
import { NVDProvider } from './providers/nvd.js';
import { AnyRunProvider } from './providers/anyrun.js';
const vt = new VirusTotalProvider();
const shodan = new ShodanProvider();
const nvd = new NVDProvider();
const anyrun = new AnyRunProvider();
const server = new Server({
    name: 'security-intelligence-server',
    version: '1.0.0',
}, {
    capabilities: {
        tools: {},
    },
});
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
        ],
    };
});
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    try {
        switch (name) {
            case 'vt_file_report':
                return { content: [{ type: 'text', text: JSON.stringify(await vt.getFileReport(args.hash)) }] };
            case 'vt_url_report':
                return { content: [{ type: 'text', text: JSON.stringify(await vt.getUrlReport(args.url)) }] };
            case 'vt_domain_report':
                return { content: [{ type: 'text', text: JSON.stringify(await vt.getDomainReport(args.domain)) }] };
            case 'vt_ip_report':
                return { content: [{ type: 'text', text: JSON.stringify(await vt.getIpReport(args.ip)) }] };
            case 'shodan_host_info':
                return { content: [{ type: 'text', text: JSON.stringify(await shodan.getHostInfo(args.ip)) }] };
            case 'shodan_search':
                return { content: [{ type: 'text', text: JSON.stringify(await shodan.searchHosts(args.query)) }] };
            case 'nvd_cve_details':
                return { content: [{ type: 'text', text: JSON.stringify(await nvd.getCveDetails(args.cveId)) }] };
            case 'nvd_search':
                return { content: [{ type: 'text', text: JSON.stringify(await nvd.searchCves(args.keyword)) }] };
            case 'anyrun_task_details':
                return { content: [{ type: 'text', text: JSON.stringify(await anyrun.getTaskDetails(args.taskId)) }] };
            case 'anyrun_search':
                return { content: [{ type: 'text', text: JSON.stringify(await anyrun.searchTasks(args.query)) }] };
            default:
                throw new Error(`Tool not found: ${name}`);
        }
    }
    catch (error) {
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
