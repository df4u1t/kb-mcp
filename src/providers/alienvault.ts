
import axios from 'axios';
import { config } from '../config.js';
import { ProviderResponse } from '../types/index.js';

const OTX_BASE_URL = 'https://otx.alienvault.com/api/v1';

export class AlienVaultOTXProvider {
  private apiKey: string;

  constructor() {
    this.apiKey = config.ALIENVAULT_OTX_API_KEY || '';
    if (!this.apiKey) {
      console.warn('AlienVault OTX API key is missing. Some tools may not work.');
    }
  }

  private async request(endpoint: string, params: any = {}): Promise<ProviderResponse> {
    try {
      const response = await axios.get(`${OTX_BASE_URL}${endpoint}`, {
        headers: { 'X-OTX-API-KEY': this.apiKey },
        params,
      });
      return {
        provider: 'AlienVault OTX',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
      if (error.response?.status === 429) {
        return {
          provider: 'AlienVault OTX',
          data: null,
          status: 'rate-limited',
          message: 'AlienVault OTX API rate limit exceeded.',
        };
      }
      return {
        provider: 'AlienVault OTX',
        data: null,
        status: 'error',
        message: error.response?.data?.error || error.message,
      };
    }
  }

  async getIndicatorGeneral(type: string, value: string): Promise<ProviderResponse> {
    // type should be IPv4, IPv6, domain, file, url
    return this.request(`/indicators/${type}/${value}/general`);
  }

  async getIndicatorPulses(type: string, value: string): Promise<ProviderResponse> {
    return this.request(`/indicators/${type}/${value}/pulses`);
  }

  async getPulseDetails(pulseId: string): Promise<ProviderResponse> {
    return this.request(`/pulses/${pulseId}`);
  }

  async searchPulses(query: string): Promise<ProviderResponse> {
    return this.request('/search/pulses', { query });
  }
}
