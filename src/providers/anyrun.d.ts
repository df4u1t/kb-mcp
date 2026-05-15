import { ProviderResponse } from '../types';
export declare class AnyRunProvider {
    private apiKey;
    constructor();
    private request;
    getTaskDetails(taskId: string): Promise<ProviderResponse>;
    searchTasks(query: string): Promise<ProviderResponse>;
}
//# sourceMappingURL=anyrun.d.ts.map