
import axios from 'axios';
import { config } from '../config.js';
import { ProviderResponse } from '../types/index.js';

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export interface NvdSearchOptions {
  keyword?: string;
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  cvssV3Severity?: string;
  resultsPerPage?: number;
  startIndex?: number;
}

export class NVDProvider {
  private apiKey: string;

  constructor() {
    this.apiKey = config.NVD_API_KEY || '';
    if (!this.apiKey) {
      console.warn('NVD API key is missing. Some tools may not work.');
    }
  }

  private async request(params: any = {}): Promise<ProviderResponse> {
    try {
      const response = await axios.get(NVD_BASE_URL, {
        params,
        headers: this.apiKey ? { 'apiKey': this.apiKey } : {},
      });
      return {
        provider: 'NVD',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
      if (error.response?.status === 429) {
        return {
          provider: 'NVD',
          data: null,
          status: 'rate-limited',
          message: 'NVD API rate limit exceeded.',
        };
      }
      return {
        provider: 'NVD',
        data: null,
        status: 'error',
        message: error.response?.data?.error || error.message,
      };
    }
  }

  async getCveDetails(cveId: string): Promise<ProviderResponse> {
    return this.request({ cveId });
  }

  async searchCves(options: NvdSearchOptions): Promise<ProviderResponse> {
    const params: any = {};

    if (options.keyword) params.keywordSearch = options.keyword;
    if (options.pubStartDate) params.pubStartDate = options.pubStartDate;
    if (options.pubEndDate) params.pubEndDate = options.pubEndDate;
    if (options.lastModStartDate) params.lastModStartDate = options.lastModStartDate;
    if (options.lastModEndDate) params.lastModEndDate = options.lastModEndDate;
    if (options.cvssV3Severity) params.cvssV3Severity = options.cvssV3Severity;
    if (options.resultsPerPage !== undefined) params.resultsPerPage = options.resultsPerPage;
    if (options.startIndex !== undefined) params.startIndex = options.startIndex;

    return this.request(params);
  }

  async getRecentCves(days: number = 7, keyword?: string, maxResults: number = 50): Promise<ProviderResponse> {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const params: any = {
      pubStartDate: startDate.toISOString(),
      pubEndDate: endDate.toISOString(),
      resultsPerPage: Math.min(maxResults, 200),
    };

    if (keyword) {
      params.keywordSearch = keyword;
    }

    return this.request(params);
  }
}
