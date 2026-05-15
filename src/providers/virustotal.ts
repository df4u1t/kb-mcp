
import axios from 'axios';
import { config } from '../config.js';
import { ProviderResponse } from '../types/index.js';

const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

export class VirusTotalProvider {
  private apiKey: string;

  constructor() {
    this.apiKey = config.VIRUSTOTAL_API_KEY || '';
    if (!this.apiKey) {
      console.warn('VirusTotal API key is missing. Some tools may not work.');
    }
  }

  private async request<T>(endpoint: string): Promise<ProviderResponse> {
    try {
      const response = await axios.get(`${VT_BASE_URL}${endpoint}`, {
        headers: { 'x-apikey': this.apiKey },
      });
      return {
        provider: 'VirusTotal',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
      if (error.response?.status === 429) {
        return {
          provider: 'VirusTotal',
          data: null,
          status: 'rate-limited',
          message: 'VirusTotal API rate limit exceeded.',
        };
      }
      return {
        provider: 'VirusTotal',
        data: null,
        status: 'error',
        message: error.response?.data?.error || error.message,
      };
    }
  }

  async getFileReport(hash: string): Promise<ProviderResponse> {
    return this.request(`/files/${hash}`);
  }

  async getUrlReport(url: string): Promise<ProviderResponse> {
    // VT requires URLs to be base64 encoded without padding for some endpoints, 
    // but for /urls/{id} it's the ID. For reports, we often use the hash of the URL.
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
    return this.request(`/urls/${urlId}`);
  }

  async getDomainReport(domain: string): Promise<ProviderResponse> {
    return this.request(`/domains/${domain}`);
  }

  async getIpReport(ip: string): Promise<ProviderResponse> {
    return this.request(`/ip_addresses/${ip}`);
  }
}
