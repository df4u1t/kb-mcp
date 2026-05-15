import { ProviderResponse } from '../types';
export declare class VirusTotalProvider {
    private apiKey;
    constructor();
    private request;
    getFileReport(hash: string): Promise<ProviderResponse>;
    getUrlReport(url: string): Promise<ProviderResponse>;
    getDomainReport(domain: string): Promise<ProviderResponse>;
    getIpReport(ip: string): Promise<ProviderResponse>;
}
//# sourceMappingURL=virustotal.d.ts.map