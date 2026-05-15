import { ProviderResponse } from '../types';
export declare class NVDProvider {
    private apiKey;
    constructor();
    private request;
    getCveDetails(cveId: string): Promise<ProviderResponse>;
    searchCves(keyword: string): Promise<ProviderResponse>;
}
//# sourceMappingURL=nvd.d.ts.map