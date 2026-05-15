import axios from 'axios';
import { config } from '../config.js';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export class NVDProvider {
    apiKey;
    constructor() {
        this.apiKey = config.NVD_API_KEY || '';
        if (!this.apiKey) {
            console.warn('NVD API key is missing. Some tools may not work.');
        }
    }
    async request(params = {}) {
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
        }
        catch (error) {
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
    async getCveDetails(cveId) {
        return this.request({ cveId });
    }
    async searchCves(keyword) {
        return this.request({ keywordSearch: keyword });
    }
}
