#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
    CallToolRequestSchema,
    ErrorCode,
    ListToolsRequestSchema,
    McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import { join, dirname } from 'path';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { IDARemoteClient } from './idaremoteclient.js';
import { exists } from 'llamaindex';
const ida = new IDARemoteClient();
const execAsync = promisify(exec);



interface RunIdaCommandArgs {
    scriptPath: string;
    outputPath?: string;
}

interface SearchImmediateValueArgs {
    value: string | number;
    radix?: number;
    startAddress?: string | number;
    endAddress?: string | number;
}

interface SearchTextArgs {
    text: string;
    caseSensitive?: boolean;
    startAddress?: string | number;
    endAddress?: string | number;
}

interface SearchByteSequenceArgs {
    bytes: string;
    startAddress?: string | number;
    endAddress?: string | number;
}

interface GetDisassemblyArgs {
    startAddress: string | number;
    endAddress?: string | number;
    count?: number;
}

interface GetFunctionsArgs {
    // No parameters required
}

interface GetExportsArgs {
    // No parameters required
}

interface GetStringsArgs {
    // No parameters required
}

const isValidRunIdaArgs = (args: any): args is RunIdaCommandArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        (typeof args.scriptPath === 'string')
    );
};

const isValidSearchImmediateValueArgs = (args: any): args is SearchImmediateValueArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        (typeof args.value === 'string' || typeof args.value === 'number')
    );
};

const isValidSearchTextArgs = (args: any): args is SearchTextArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        typeof args.text === 'string'
    );
};

const isValidSearchByteSequenceArgs = (args: any): args is SearchByteSequenceArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        typeof args.bytes === 'string'
    );
};

const isValidGetDisassemblyArgs = (args: any): args is GetDisassemblyArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        (typeof args.startAddress === 'string' || typeof args.startAddress === 'number')
    );
};

const isValidGetFunctionsArgs = (args: any): args is GetFunctionsArgs => {
    return (
        typeof args === 'object' &&
        args !== null
    );
};

const isValidGetExportsArgs = (args: any): args is GetExportsArgs => {
    return (
        typeof args === 'object' &&
        args !== null
    );
};

const isValidGetStringsArgs = (args: any): args is GetStringsArgs => {
    return (
        typeof args === 'object' &&
        args !== null
    );
};

class IdaServer {
    private server: Server;

    constructor() {
        this.server = new Server(
            {
                name: 'ida-pro-server',
                version: '1.0.0',
            },
            {
                capabilities: {
                    tools: {}, // Will be populated in setup

                },
            }
        );

        this.setupToolHandlers();

        // Error handling
        this.server.onerror = (error) => console.error('[MCP Error]', error);
        process.on('SIGINT', async () => {
            await this.server.close();
            process.exit(0);
        });
    }

    private setupToolHandlers() {
        this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
            tools: [

                {
                    name: 'run_ida_command',
                    description: 'Execute an IDA Pro Script (IdaPython, Version IDA 8.3)',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            scriptPath: {
                                type: 'string',
                                description: 'absolute Path to the script file to execute',
                            },
                            outputPath: {
                                type: 'string',
                                description: 'absolute Path to save the scripts output to',
                            },
                        },
                        required: ['scriptPath'],
                    },
                },
                {
                    name: 'search_immediate_value',
                    description: 'Search for immediate values in the binary',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            value: {
                                type: 'string',
                                description: 'Value to search for (number or string)',
                            },
                            radix: {
                                type: 'number',
                                description: 'Radix for number conversion (default: 16)',
                            },
                            startAddress: {
                                type: 'string',
                                description: 'Start address for search (optional)',
                            },
                            endAddress: {
                                type: 'string',
                                description: 'End address for search (optional)',
                            },
                        },
                        required: ['value'],
                    },
                },
                {
                    name: 'search_text',
                    description: 'Search for text in the binary',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            text: {
                                type: 'string',
                                description: 'Text to search for',
                            },
                            caseSensitive: {
                                type: 'boolean',
                                description: 'Whether the search is case sensitive (default: false)',
                            },
                            startAddress: {
                                type: 'string',
                                description: 'Start address for search (optional)',
                            },
                            endAddress: {
                                type: 'string',
                                description: 'End address for search (optional)',
                            },
                        },
                        required: ['text'],
                    },
                },
                {
                    name: 'search_byte_sequence',
                    description: 'Search for a byte sequence in the binary',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            bytes: {
                                type: 'string',
                                description: 'Byte sequence to search for (e.g., "90 90 90" for three NOPs)',
                            },
                            startAddress: {
                                type: 'string',
                                description: 'Start address for search (optional)',
                            },
                            endAddress: {
                                type: 'string',
                                description: 'End address for search (optional)',
                            },
                        },
                        required: ['bytes'],
                    },
                },
                {
                    name: 'get_disassembly',
                    description: 'Get disassembly for an address range',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            startAddress: {
                                type: 'string',
                                description: 'Start address for disassembly',
                            },
                            endAddress: {
                                type: 'string',
                                description: 'End address for disassembly (optional)',
                            },
                            count: {
                                type: 'number',
                                description: 'Number of instructions to disassemble (optional)',
                            },
                        },
                        required: ['startAddress'],
                    },
                },
                {
                    name: 'get_functions',
                    description: 'Get list of functions from the binary',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                        required: [],
                    },
                },
                {
                    name: 'get_exports',
                    description: 'Get list of exports from the binary',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                        required: [],
                    },
                },
                {
                    name: 'get_strings',
                    description: 'Get list of strings from the binary',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                        required: [],
                    },
                },
            ],
        }));



        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            // Handle different tool types based on the tool name
            switch (request.params.name) {
                case 'run_ida_command':
                    if (!isValidRunIdaArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid ida command arguments'
                        );
                    }

                    try {
                        const { scriptPath, outputPath } = request.params.arguments;

                        // Verify IDA executable exists
                        if (!existsSync(scriptPath)) {
                            return {
                                content: [
                                    {
                                        type: 'text',
                                        text: `Error: IDA Pro script not found at ${scriptPath}. Make sure the path is correct.`,
                                    },
                                ],
                                isError: true,
                            };
                        }

                        let result = await ida.executeScriptByPath(scriptPath);

                        if (result.error) {
                            return {
                                content: [
                                    {
                                        type: 'text',
                                        text: `Error executing IDA Pro script: ${result.error}`,
                                    },
                                ],
                                isError: true,
                            };
                        }
                        if (outputPath && typeof outputPath === 'string') {
                            writeFileSync(outputPath, result.output);
                            return {
                                content: [
                                    {
                                        type: 'text',
                                        text: `IDA Pro Script Execution Results saved to: ${outputPath}`,
                                    },
                                ],
                            };
                        }

                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `IDA Pro Script Execution Results:\n\n${result.output}`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error executing IDA Pro command: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'search_immediate_value':
                    if (!isValidSearchImmediateValueArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid search immediate value arguments'
                        );
                    }

                    try {
                        const { value, radix, startAddress, endAddress } = request.params.arguments;
                        
                        const result = await ida.searchForImmediateValue(value, {
                            radix,
                            startAddress,
                            endAddress
                        });
                        
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Found ${result.count} occurrences of immediate value ${value}:\n\n${
                                        JSON.stringify(result.results, null, 2)
                                    }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error searching for immediate value: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'search_text':
                    if (!isValidSearchTextArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid search text arguments'
                        );
                    }

                    try {
                        const { text, caseSensitive, startAddress, endAddress } = request.params.arguments;
                        
                        const result = await ida.searchForText(text, {
                            caseSensitive,
                            startAddress,
                            endAddress
                        });
                        
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Found ${result.count} occurrences of text "${text}":\n\n${
                                        JSON.stringify(result.results, null, 2)
                                    }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error searching for text: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'search_byte_sequence':
                    if (!isValidSearchByteSequenceArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid search byte sequence arguments'
                        );
                    }

                    try {
                        const { bytes, startAddress, endAddress } = request.params.arguments;
                        
                        const result = await ida.searchForByteSequence(bytes, {
                            startAddress,
                            endAddress
                        });
                        
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Found ${result.count} occurrences of byte sequence "${bytes}":\n\n${
                                        JSON.stringify(result.results, null, 2)
                                    }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error searching for byte sequence: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'get_disassembly':
                    if (!isValidGetDisassemblyArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid disassembly arguments'
                        );
                    }

                    try {
                        const { startAddress, endAddress, count } = request.params.arguments;
                        
                        const result = await ida.getDisassembly(startAddress, {
                            endAddress,
                            count
                        });
                        
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Disassembly from ${result.start_address}${result.end_address ? ` to ${result.end_address}` : ''}:\n\n${
                                        JSON.stringify(result.disassembly, null, 2)
                                    }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error getting disassembly: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'get_functions':
                    if (!isValidGetFunctionsArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid get functions arguments'
                        );
                    }

                    try {
                        const result = await ida.getFunctions();
                        
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Retrieved ${result.count} functions from the binary:\n\n${
                                        JSON.stringify(result.functions, null, 2)
                                    }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error getting functions: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'get_exports':
                    if (!isValidGetExportsArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid get exports arguments'
                        );
                    }

                    try {
                        const result = await ida.getExports();
                        
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Retrieved ${result.count} exports from the binary:\n\n${
                                        JSON.stringify(result.exports, null, 2)
                                    }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error getting exports: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'get_strings':
                    if (!isValidGetStringsArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid get strings arguments'
                        );
                    }

                    try {
                        const result = await ida.getStrings();
                        
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Retrieved ${result.count} strings from the binary:\n\n${
                                        JSON.stringify(result.strings, null, 2)
                                    }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error getting strings: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                default:
                    throw new McpError(
                        ErrorCode.MethodNotFound,
                        `Unknown tool: ${request.params.name}`
                    );
            }
        });
    }

    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error('IDA Pro MCP server running on stdio');
    }
}

const server = new IdaServer();
server.run().catch(console.error);