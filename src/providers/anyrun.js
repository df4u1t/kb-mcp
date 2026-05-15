import axios from 'axios';
import { config } from '../config.js';
const ANYRUN_BASE_URL = 'https://api.any.run';
export class AnyRunProvider {
    apiKey;
    constructor() {
        this.apiKey = config.ANYRUN_API_KEY || '';
        if (!this.apiKey) {
            console.warn('AnyRun API key is missing. Some tools may not work.');
        }
    }
    async request(endpoint, params = {}) {
        try {
            const response = await axios.get(`${ANYRUN_BASE_URL}${endpoint}`, {
                params: { ...params, api_key: this.apiKey },
            });
            return {
                provider: 'AnyRun',
                data: response.data,
                status: 'success',
            };
        }
        catch (error) {
            if (error.response?.status === 429) {
                return {
                    provider: 'AnyRun',
                    data: null,
                    status: 'rate-limited',
                    message: 'AnyRun API rate limit exceeded.',
                };
            }
            return {
                provider: 'AnyRun',
                data: null,
                status: 'error',
                message: error.response?.data?.error || error.message,
            };
        }
    }
    async getTaskDetails(taskId) {
        return this.request(`/tasks/${taskId}`);
    }
    async searchTasks(query) {
        return this.request('/tasks/search', { query });
    }
}
