# Security Intelligence MCP Server

A Model Context Protocol (MCP) server that provides a unified interface for security analysts to gather threat intelligence from VirusTotal, Shodan, NVD, AnyRun, AlienVault OTX, and GitHub.

## Features

This server implements a set of tools that allow an LLM to perform the following operations:

### VirusTotal
- `vt_file_report`: Retrieve analysis reports for file hashes (MD5, SHA1, SHA256).
- `vt_url_report`: Retrieve analysis reports for URLs.
- `vt_domain_report`: Retrieve analysis reports for domains.
- `vt_ip_report`: Retrieve analysis reports for IP addresses.

### Shodan
- `shodan_host_info`: Get detailed host information for a specific IP.
- `shodan_search`: Search for hosts matching a specific query.

### NVD (National Vulnerability Database)
- `nvd_cve_details`: Get detailed information for a specific CVE ID.
- `nvd_search`: Search for CVEs using keywords with optional date range filtering (`daysBack`, `pubStartDate`/`pubEndDate`, `lastModStartDate`/`lastModEndDate`), pagination (`resultsPerPage`, `startIndex`).

### AnyRun
- `anyrun_task_details`: Get details for a specific sandbox task.
- `anyrun_search`: Search for tasks matching a query.
- `anyrun_submit_url`: Submit a URL for analysis.
- `anyrun_submit_file`: Submit a local file for analysis.
- `anyrun_get_report`: Retrieve the final analysis report.

### AlienVault OTX
- `otx_indicator_details`: Get detailed information for an indicator. Returns all available sections (reputation, geo, malware, url_list, passive_dns, analysis) or a specific section if requested. Supports types: IPv4, IPv6, domain, hostname, file, url.
- `otx_indicator_pulses`: Find all OTX Pulses associated with an indicator.
- `otx_pulse_details`: Get full details of a specific threat pulse.
- `otx_search_pulses`: Search for pulses by keyword.
- `otx_subscribed_pulses`: Get your subscribed pulse feed (paginated).
- `otx_recent_activity`: Get recent OTX community activity (paginated).

### GitHub
- `github_search_advisories`: Search GitHub for security advisories and vulnerability discussions.
- `github_search_poc`: Search GitHub for exploit PoC code related to a CVE or vulnerability.

## Quick Start Guide

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher)
- API Keys for the following services:
  - VirusTotal
  - Shodan
  - NVD
  - AnyRun
  - AlienVault OTX
  - GitHub

### Installation

1. Clone the repository or navigate to the project folder:
   ```bash
   cd kb-mcp
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   Create a `.env` file in the root directory and add your API keys:
   ```env
   VIRUSTOTAL_API_KEY=your_vt_key_here
   SHODAN_API_KEY=your_shodan_key_here
   NVD_API_KEY=your_nvd_key_here
   ANYRUN_API_KEY=your_anyrun_key_here
   ALIENVAULT_OTX_API_KEY=your_otx_key_here
   GITHUB_TOKEN=your_github_token_here
   ```

4. Build the project:
   ```bash
   npm run build
   ```

### Running the Server

You can start the server in stdio mode:
```bash
npm start
```

### Integration with MCP Clients (e.g., Claude Desktop)

Add the following configuration to your MCP settings file:

```json
{
  "mcpServers": {
    "security-intelligence": {
      "command": "node",
      "args": ["FULL_PATH_TO/kb-mcp/dist/index.js"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_vt_key",
        "SHODAN_API_KEY": "your_shodan_key",
        "NVD_API_KEY": "your_nvd_key",
        "ANYRUN_API_KEY": "your_anyrun_key",
        "ALIENVAULT_OTX_API_KEY": "your_otx_key",
        "GITHUB_TOKEN": "your_github_token"
      }
    }
  }
}
```

Alternatively, if your client uses YAML configuration:

```yaml
mcpServers:
  security-intelligence:
    command: "node"
    args:
      - "FULL_PATH_TO/kb-mcp/dist/index.js"
    env:
      VIRUSTOTAL_API_KEY: "your_vt_key"
      SHODAN_API_KEY: "your_shodan_key"
      NVD_API_KEY: "your_nvd_key"
      ANYRUN_API_KEY: "your_anyrun_key"
      ALIENVAULT_OTX_API_KEY: "your_otx_key"
      GITHUB_TOKEN: "your_github_token"
```

## Architecture

The server uses a provider-based architecture where each security service is encapsulated in its own provider class. This ensures that API-specific logic (authentication, rate limiting, and data formatting) is isolated from the MCP tool definitions.

- `src/index.ts`: Main server entry point and tool routing.
- `src/providers/`: Individual API clients for each service.
- `src/config.ts`: Environment variable management.
- `src/types/`: Shared TypeScript interfaces.
