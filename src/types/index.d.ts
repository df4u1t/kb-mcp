export interface SecurityIndicator {
    value: string;
    type: 'ip' | 'domain' | 'hash' | 'url';
}
export interface ProviderResponse {
    provider: string;
    data: any;
    status: 'success' | 'error' | 'rate-limited';
    message?: string;
}
//# sourceMappingURL=index.d.ts.map