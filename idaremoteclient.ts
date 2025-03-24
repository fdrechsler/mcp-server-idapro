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
 * Immediate value search result from /api/search/immediate endpoint
 */
export interface ImmediateSearchResult {
    address: string;
    instruction: string;
    value: number;
    operand_index: number;
}

/**
 * Response from /api/search/immediate endpoint
 */
export interface ImmediateSearchResponse {
    count: number;
    results: ImmediateSearchResult[];
    error?: string;
}

/**
 * Text search result from /api/search/text endpoint
 */
export interface TextSearchResult {
    address: string;
    value: string;
    length: number;
    type: 'c' | 'pascal';
}

/**
 * Response from /api/search/text endpoint
 */
export interface TextSearchResponse {
    count: number;
    results: TextSearchResult[];
    error?: string;
}

/**
 * Byte sequence search result from /api/search/bytes endpoint
 */
export interface ByteSequenceSearchResult {
    address: string;
    disassembly: string;
    bytes: string;
}

/**
 * Response from /api/search/bytes endpoint
 */
export interface ByteSequenceSearchResponse {
    count: number;
    results: ByteSequenceSearchResult[];
    error?: string;
}

/**
 * Disassembly instruction from /api/disassembly endpoint
 */
export interface DisassemblyInstruction {
    address: string;
    disassembly: string;
    bytes: string;
    size: number;
}

/**
 * Response from /api/disassembly endpoint
 */
export interface DisassemblyResponse {
    count: number;
    disassembly: DisassemblyInstruction[];
    start_address: string;
    end_address?: string;
    error?: string;
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
     * Search for immediate values in the binary
     * @param value The value to search for (number or string)
     * @param options Optional search parameters
     * @returns Search results
     */
    async searchForImmediateValue(
        value: number | string,
        options: {
            radix?: number;
            startAddress?: number | string;
            endAddress?: number | string;
        } = {}
    ): Promise<ImmediateSearchResponse> {
        const params = new URLSearchParams();
        params.append('value', value.toString());
        
        if (options.radix !== undefined) {
            params.append('radix', options.radix.toString());
        }
        
        if (options.startAddress !== undefined) {
            const startAddr = typeof options.startAddress === 'string'
                ? options.startAddress
                : options.startAddress.toString();
            params.append('start', startAddr);
        }
        
        if (options.endAddress !== undefined) {
            const endAddr = typeof options.endAddress === 'string'
                ? options.endAddress
                : options.endAddress.toString();
            params.append('end', endAddr);
        }
        
        return this.get<ImmediateSearchResponse>(`/search/immediate?${params.toString()}`);
    }

    /**
     * Search for text in the binary
     * @param text The text to search for
     * @param options Optional search parameters
     * @returns Search results
     */
    async searchForText(
        text: string,
        options: {
            caseSensitive?: boolean;
            startAddress?: number | string;
            endAddress?: number | string;
        } = {}
    ): Promise<TextSearchResponse> {
        const params = new URLSearchParams();
        params.append('text', text);
        
        if (options.caseSensitive !== undefined) {
            params.append('case_sensitive', options.caseSensitive.toString());
        }
        
        if (options.startAddress !== undefined) {
            const startAddr = typeof options.startAddress === 'string'
                ? options.startAddress
                : options.startAddress.toString();
            params.append('start', startAddr);
        }
        
        if (options.endAddress !== undefined) {
            const endAddr = typeof options.endAddress === 'string'
                ? options.endAddress
                : options.endAddress.toString();
            params.append('end', endAddr);
        }
        
        return this.get<TextSearchResponse>(`/search/text?${params.toString()}`);
    }

    /**
     * Search for a byte sequence in the binary
     * @param byteSequence The byte sequence to search for (e.g., "90 90 90" for three NOPs)
     * @param options Optional search parameters
     * @returns Search results
     */
    async searchForByteSequence(
        byteSequence: string,
        options: {
            startAddress?: number | string;
            endAddress?: number | string;
        } = {}
    ): Promise<ByteSequenceSearchResponse> {
        const params = new URLSearchParams();
        params.append('bytes', byteSequence);
        
        if (options.startAddress !== undefined) {
            const startAddr = typeof options.startAddress === 'string'
                ? options.startAddress
                : options.startAddress.toString();
            params.append('start', startAddr);
        }
        
        if (options.endAddress !== undefined) {
            const endAddr = typeof options.endAddress === 'string'
                ? options.endAddress
                : options.endAddress.toString();
            params.append('end', endAddr);
        }
        
        return this.get<ByteSequenceSearchResponse>(`/search/bytes?${params.toString()}`);
    }

    /**
     * Get disassembly for an address range
     * @param startAddress The starting address
     * @param options Optional parameters
     * @returns Disassembly instructions
     */
    async getDisassembly(
        startAddress: number | string,
        options: {
            endAddress?: number | string;
            count?: number;
        } = {}
    ): Promise<DisassemblyResponse> {
        const params = new URLSearchParams();
        
        const startAddr = typeof startAddress === 'string'
            ? startAddress
            : startAddress.toString();
        params.append('start', startAddr);
        
        if (options.endAddress !== undefined) {
            const endAddr = typeof options.endAddress === 'string'
                ? options.endAddress
                : options.endAddress.toString();
            params.append('end', endAddr);
        }
        
        if (options.count !== undefined) {
            params.append('count', options.count.toString());
        }
        
        return this.get<DisassemblyResponse>(`/disassembly?${params.toString()}`);
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