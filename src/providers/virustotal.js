import axios from 'axios';
import { config } from '../config.js';
const VT_BASE_URL = 'https://www.virustotal.com/api/v3';
export class VirusTotalProvider {
    apiKey;
    constructor() {
        this.apiKey = config.VIRUSTOTAL_API_KEY || '';
        if (!this.apiKey) {
            console.warn('VirusTotal API key is missing. Some tools may not work.');
        }
    }
    async request(endpoint) {
        try {
            const response = await axios.get(`${VT_BASE_URL}${endpoint}`, {
                headers: { 'x-apikey': this.apiKey },
            });
            return {
                provider: 'VirusTotal',
                data: response.data,
                status: 'success',
            };
        }
        catch (error) {
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
    async getFileReport(hash) {
        return this.request(`/files/${hash}`);
    }
    async getUrlReport(url) {
        // VT requires URLs to be base64 encoded without padding for some endpoints, 
        // but for /urls/{id} it's the ID. For reports, we often use the hash of the URL.
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
        return this.request(`/urls/${urlId}`);
    }
    async getDomainReport(domain) {
        return this.request(`/domains/${domain}`);
    }
    async getIpReport(ip) {
        return this.request(`/ip_addresses/${ip}`);
    }
}
