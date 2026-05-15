
import axios from 'axios';
import { config } from '../config.js';
import { ProviderResponse } from '../types/index.js';

const GITHUB_BASE_URL = 'https://api.github.com';

export class GitHubProvider {
  private token: string;

  constructor() {
    this.token = config.GITHUB_TOKEN || '';
    if (!this.token) {
      console.warn('GitHub Token is missing. Some tools may not work or will be heavily rate-limited.');
    }
  }

  private async request(endpoint: string, params: any = {}): Promise<ProviderResponse> {
    try {
      const response = await axios.get(`${GITHUB_BASE_URL}${endpoint}`, {
        headers: { 
          'Authorization': `Bearer ${this.token}`,
          'User-Agent': 'kb-mcp-security-server',
          'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28'
        },
        params,
      });
      return {
        provider: 'GitHub',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
      if (error.response?.status === 403) {
        return {
          provider: 'GitHub',
          data: null,
          status: 'rate-limited',
          message: 'GitHub API rate limit exceeded.',
        };
      }
      return {
        provider: 'GitHub',
        data: null,
        status: 'error',
        message: error.response?.data?.message || error.message,
      };
    }
  }

  async searchAdvisories(query: string): Promise<ProviderResponse> {
    // Search for issues/PRs in the advisory database or general security discussions
    // We use the search/issues endpoint as it covers GHSA and related discussions
    return this.request('/search/issues', { 
      q: `${query} is:issue`,
      per_page: 20 
    });
  }

  async searchExploitPoC(cveId: string): Promise<ProviderResponse> {
    // Construct a query to find PoCs: CVE ID + keywords like 'exploit' or 'poc'
    const query = `${cveId} exploit poc payload`;
    return this.request('/search/code', { 
      q: query,
      per_page: 20 
    });
  }

  async getRepoDetails(repoFullName: string): Promise<ProviderResponse> {
    return this.request(`/repos/${repoFullName}`);
  }
}
