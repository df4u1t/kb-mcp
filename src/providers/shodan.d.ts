import { ProviderResponse } from '../types';
export declare class ShodanProvider {
    private apiKey;
    constructor();
    private request;
    getHostInfo(ip: string): Promise<ProviderResponse>;
    searchHosts(query: string): Promise<ProviderResponse>;
    getDnsInfo(domain: string): Promise<ProviderResponse>;
}
//# sourceMappingURL=shodan.d.ts.map