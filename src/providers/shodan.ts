
import axios from 'axios';
import { config } from '../config.js';
import { ProviderResponse } from '../types/index.js';

const SHODAN_BASE_URL = 'https://api.shodan.io';

export class ShodanProvider {
  private apiKey: string;

  constructor() {
    this.apiKey = config.SHODAN_API_KEY || '';
    if (!this.apiKey) {
      console.warn('Shodan API key is missing. Some tools may not work.');
    }
  }

  private async request<T>(endpoint: string, params: any = {}): Promise<ProviderResponse> {
    try {
      const response = await axios.get(`${SHODAN_BASE_URL}${endpoint}`, {
        params: { ...params, key: this.apiKey },
      });
      return {
        provider: 'Shodan',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
      if (error.response?.status === 429) {
        return {
          provider: 'Shodan',
          data: null,
          status: 'rate-limited',
          message: 'Shodan API rate limit exceeded.',
        };
      }
      return {
        provider: 'Shodan',
        data: null,
        status: 'error',
        message: error.response?.data?.error || error.message,
      };
    }
  }

  async getHostInfo(ip: string): Promise<ProviderResponse> {
    return this.request(`/shodan/host/${ip}`);
  }

  async searchHosts(query: string): Promise<ProviderResponse> {
    return this.request('/shodan/host/search', { query });
  }

  async getDnsInfo(domain: string): Promise<ProviderResponse> {
    return this.request(`/dns/domain/${domain}`);
  }
}
