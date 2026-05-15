
import axios from 'axios';
import { config } from '../config.js';
import { ProviderResponse } from '../types/index.js';

const OTX_BASE_URL = 'https://otx.alienvault.com/api/v1';

// Maps indicator types to their available API sections
const INDICATOR_SECTIONS: Record<string, string[]> = {
  IPv4: ['general', 'reputation', 'geo', 'malware', 'url_list', 'passive_dns'],
  IPv6: ['general', 'reputation', 'geo', 'malware', 'url_list', 'passive_dns'],
  domain: ['general', 'geo', 'malware', 'url_list', 'passive_dns'],
  hostname: ['general', 'geo', 'malware', 'url_list', 'passive_dns'],
  url: ['general', 'url_list'],
  file: ['general', 'analysis'],
};

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

  /**
   * Get indicator details for a specific section, or all available sections.
   * @param type - Indicator type: IPv4, IPv6, domain, hostname, url, file
   * @param value - The indicator value
   * @param section - Optional specific section. If omitted, all sections are fetched.
   */
  async getIndicatorDetails(type: string, value: string, section?: string): Promise<ProviderResponse> {
    const sections = INDICATOR_SECTIONS[type];
    if (!sections) {
      return {
        provider: 'AlienVault OTX',
        data: null,
        status: 'error',
        message: `Unsupported indicator type: ${type}. Supported types: ${Object.keys(INDICATOR_SECTIONS).join(', ')}`,
      };
    }

    // If a specific section is requested
    if (section) {
      if (!sections.includes(section)) {
        return {
          provider: 'AlienVault OTX',
          data: null,
          status: 'error',
          message: `Section "${section}" is not available for type "${type}". Available sections: ${sections.join(', ')}`,
        };
      }
      return this.request(`/indicators/${type}/${value}/${section}`);
    }

    // Fetch all sections in parallel
    try {
      const results = await Promise.all(
        sections.map(async (sec) => {
          const response = await axios.get(`${OTX_BASE_URL}/indicators/${type}/${value}/${sec}`, {
            headers: { 'X-OTX-API-KEY': this.apiKey },
          });
          return { section: sec, data: response.data };
        })
      );

      const combined: Record<string, any> = {};
      for (const result of results) {
        combined[result.section] = result.data;
      }

      return {
        provider: 'AlienVault OTX',
        data: combined,
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

  async searchPulses(query: string, page: number = 1, limit: number = 25, modifiedSince?: string): Promise<ProviderResponse> {
    // If modifiedSince is provided, use the subscribed pulses endpoint with date filtering
    // and apply keyword as a client-side filter (search endpoint doesn't support date filtering)
    if (modifiedSince) {
      const response = await this.request('/pulses/subscribed', {
        modified_since: modifiedSince,
        limit: Math.min(limit, 200),
      });

      // Apply keyword filter client-side if needed
      if (query && response.status === 'success') {
        const data = response.data as any;
        if (data?.results) {
          const lowerQuery = query.toLowerCase();
          data.results = data.results.filter((pulse: any) =>
            (pulse.name && pulse.name.toLowerCase().includes(lowerQuery)) ||
            (pulse.description && pulse.description.toLowerCase().includes(lowerQuery)) ||
            (pulse.tags && pulse.tags.some((t: string) => t.toLowerCase().includes(lowerQuery)))
          );
          data.count = data.results.length;
        }
      }

      return response;
    }

    // Without modifiedSince, use the search endpoint (relevance-based)
    return this.request('/search/pulses', { q: query, page, limit });
  }

  /**
   * Get the user's subscribed pulse feed (paginated).
   */
  async getSubscribedPulses(page: number = 1, limit: number = 20): Promise<ProviderResponse> {
    return this.request('/pulses/subscribed', { page, limit });
  }

  /**
   * Get recent OTX community activity (paginated).
   */
  async getRecentActivity(page: number = 1, limit: number = 20): Promise<ProviderResponse> {
    return this.request('/pulses/activity', { page, limit });
  }
}
