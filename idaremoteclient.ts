/**
 * IDA Pro Remote Control SDK
 * 
 * A TypeScript SDK for interacting with the IDA Pro Remote Control Server.
 * Provides type-safe methods for all endpoints of the IDA Pro Remote Control plugin.
 */

// Type definitions for responses

/**
 * Response from /api/info endpoint
 */
export interface InfoResponse {
    plugin_name: string;
    plugin_version: string;
    ida_version: string;
    file_name: string;
    endpoints: {
        path: string;
        method: string;
        description: string;
    }[];
}

/**
 * Response from /api/execute endpoint
 */
export interface ExecuteResponse {
    success: boolean;
    output: string;
    return_value?: any;
    error?: string;
}

/**
 * String information from /api/strings endpoint
 */
export interface StringInfo {
    address: string;
    value: string;
    length: number;
    type: 'c' | 'pascal';
}

/**
 * Response from /api/strings endpoint
 */
export interface StringsResponse {
    count: number;
    strings: StringInfo[];
}

/**
 * Export information from /api/exports endpoint
 */
export interface ExportInfo {
    address: string;
    name: string;
    ordinal: number;
}

/**
 * Response from /api/exports endpoint
 */
export interface ExportsResponse {
    count: number;
    exports: ExportInfo[];
}

/**
 * Import information from /api/imports endpoint
 */
export interface ImportInfo {
    address: string;
    name: string;
    ordinal: number;
}

/**
 * Response from /api/imports endpoint
 */
export interface ImportsResponse {
    count: number;
    imports: ImportInfo[];
}

/**
 * Function information from /api/functions endpoint
 */
export interface FunctionInfo {
    address: string;
    name: string;
    size: number;
    start: string;
    end: string;
    flags: number;
}

/**
 * Response from /api/functions endpoint
 */
export interface FunctionsResponse {
    count: number;
    functions: FunctionInfo[];
}

/**
 * Error response from any endpoint
 */
export interface ErrorResponse {
    error: string;
}

/**
 * Options for IDARemoteClient
 */
export interface IDARemoteClientOptions {
    /** Server host (default: 127.0.0.1) */
    host?: string;
    /** Server port (default: 9045) */
    port?: number;
    /** Request timeout in milliseconds (default: 30000) */
    timeout?: number;
}

/**
 * Client for IDA Pro Remote Control Server
 */
export class IDARemoteClient {
    private baseUrl: string;
    private timeout: number;

    /**
     * Create a new IDA Pro Remote Control client
     * @param options Configuration options
     */
    constructor(options: IDARemoteClientOptions = {}) {
        const host = options.host || '127.0.0.1';
        const port = options.port || 9045;
        this.timeout = options.timeout || 30000;
        this.baseUrl = `http://${host}:${port}/api`;
    }

    /**
     * Get information about the IDA Pro Remote Control server
     * @returns Server information
     */
    async getInfo(): Promise<InfoResponse> {
        return this.get<InfoResponse>('/info');
    }

    /**
     * Execute a Python script in IDA Pro
     * @param script Python script to execute
     * @returns Script execution results
     */
    async executeScript(script: string, logHTTP = false): Promise<ExecuteResponse> {

        return this.post<ExecuteResponse>('/execute', { script });
    }

    /**
 * Execute a Python script in IDA Pro
 * @param script Python script to execute
 * @returns Script execution results
 */
    async executeScriptByPath(path: string, logHTTP = false): Promise<ExecuteResponse> {

        return this.post<ExecuteResponse>('/executeByPath', { path });
    }

    /**
     * Get strings from the binary
     * @returns List of strings in the binary
     */
    async getStrings(): Promise<StringsResponse> {
        return this.get<StringsResponse>('/strings');
    }

    /**
     * Get exports from the binary
     * @returns List of exports in the binary
     */
    async getExports(): Promise<ExportsResponse> {
        return this.get<ExportsResponse>('/exports');
    }

    /**
     * Get imports from the binary
     * @returns List of imports in the binary
     */
    async getImports(): Promise<ImportsResponse> {
        return this.get<ImportsResponse>('/imports');
    }

    /**
     * Get functions from the binary
     * @returns List of functions in the binary
     */
    async getFunctions(): Promise<FunctionsResponse> {
        return this.get<FunctionsResponse>('/functions');
    }

    /**
     * Make a GET request to the server
     * @param endpoint API endpoint
     * @returns Response data
     */
    private async get<T>(endpoint: string): Promise<T> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, {
                method: 'GET',
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorData = await response.json() as ErrorResponse;
                throw new Error(errorData.error || `HTTP Error: ${response.status}`);
            }

            return await response.json() as T;
        } catch (error) {
            if (error instanceof DOMException && error.name === 'AbortError') {
                throw new Error(`Request to ${endpoint} timed out after ${this.timeout}ms`);
            }
            throw error;
        }
    }

    /**
     * Make a POST request to the server
     * @param endpoint API endpoint
     * @param data Request data
     * @returns Response data
     */
    private async post<T>(endpoint: string, data: any): Promise<T> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorData = await response.json() as ErrorResponse;
                throw new Error(errorData.error || `HTTP Error: ${response.status}`);
            }

            return await response.json() as T;
        } catch (error) {
            if (error instanceof DOMException && error.name === 'AbortError') {
                throw new Error(`Request to ${endpoint} timed out after ${this.timeout}ms`);
            }
            throw error;
        }
    }
}

// Example usage
/*
async function main() {
  const ida = new IDARemoteClient();
  
  try {
    // Get server info
    const info = await ida.getInfo();
    console.log('Connected to:', info.plugin_name, info.plugin_version);
    
    // Execute a script
    const scriptResult = await ida.executeScript(`
      import idautils
      
      # Count functions
      function_count = len(list(idautils.Functions()))
      print(f"Binary has {function_count} functions")
      
      # Return data
      return_value = function_count
    `);
    
    console.log('Script output:', scriptResult.output);
    console.log('Return value:', scriptResult.return_value);
    
    // Get functions
    const functions = await ida.getFunctions();
    console.log(`Retrieved ${functions.count} functions`);
    
    // Display first 5 functions
    functions.functions.slice(0, 5).forEach(func => {
      console.log(`${func.name} at ${func.address} (size: ${func.size})`);
    });
  } catch (error) {
    console.error('Error:', error.message);
  }
}
 
main();
*/