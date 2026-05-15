import axios, { AxiosRequestConfig } from 'axios';
import FormData from 'form-data';
import { config } from '../config.js';
import { ProviderResponse } from '../types/index.js';

const ANYRUN_BASE_URL = 'https://api.any.run';

export class AnyRunProvider {
  private apiKey: string;

  constructor() {
    this.apiKey = config.ANYRUN_API_KEY || '';
    if (!this.apiKey) {
      console.warn('AnyRun API key is missing. Some tools may not work.');
    }
  }

  private async request(endpoint: string, options: AxiosRequestConfig = {}): Promise<ProviderResponse> {
    try {
      const response = await axios.get(`${ANYRUN_BASE_URL}${endpoint}`, {
        ...options,
        params: { 
          ...options.params, 
          api_key: this.apiKey 
        },
      });
      return {
        provider: 'AnyRun',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
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

  async getTaskDetails(taskId: string): Promise<ProviderResponse> {
    return this.request(`/tasks/${taskId}`);
  }

  async searchTasks(query: string): Promise<ProviderResponse> {
    return this.request('/tasks/search', { params: { query } });
  }

  async submitUrl(url: string): Promise<ProviderResponse> {
    try {
      const response = await axios.post(`${ANYRUN_BASE_URL}/tasks/create`, 
        { url }, 
        { 
          headers: { 'Authorization': `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' } 
        }
      );
      return {
        provider: 'AnyRun',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
      return {
        provider: 'AnyRun',
        data: null,
        status: 'error',
        message: error.response?.data?.error || error.message,
      };
    }
  }

  async submitFile(filePath: string): Promise<ProviderResponse> {
    try {
      const fs = await import('fs');
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));
      
      const response = await axios.post(`${ANYRUN_BASE_URL}/tasks/upload`, form, {
        headers: { 
          ...form.getHeaders(),
          'Authorization': `Bearer ${this.apiKey}`
        },
      });
      return {
        provider: 'AnyRun',
        data: response.data,
        status: 'success',
      };
    } catch (error: any) {
      return {
        provider: 'AnyRun',
        data: null,
        status: 'error',
        message: error.response?.data?.error || error.message,
      };
    }
  }

  async getAnalysisReport(taskId: string): Promise<ProviderResponse> {
    return this.request(`/tasks/${taskId}/report`);
  }
}
