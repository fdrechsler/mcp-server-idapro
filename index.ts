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
import { Collection, Document, MongoClient } from 'mongodb'
const url = 'mongodb://localhost:27017';
const client = new MongoClient(url);
const dbName = "strings"

let db
let collection: Collection<Document>


interface RunIdaCommandArgs {
    scriptPath: string;
    outputPath?: string;
}
interface RunIdaDirectCommandArgs {
    script: string;
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

interface SearchInNamesArgs {
    pattern: string;
    caseSensitive?: boolean;
    type?: 'function' | 'data' | 'import' | 'export' | 'label' | 'all';
}

interface GetXrefsToArgs {
    address: string | number;
    type?: 'code' | 'data' | 'all';
}

interface GetXrefsFromArgs {
    address: string | number;
    type?: 'code' | 'data' | 'all';
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

const isValidRunIdaArgs = (args: any): args is RunIdaDirectCommandArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        (typeof args.script === 'string')
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

const isValidSearchInNamesArgs = (args: any): args is SearchInNamesArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        typeof args.pattern === 'string'
    );
};

const isValidGetXrefsToArgs = (args: any): args is GetXrefsToArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        (typeof args.address === 'string' || typeof args.address === 'number')
    );
};

const isValidGetXrefsFromArgs = (args: any): args is GetXrefsFromArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        (typeof args.address === 'string' || typeof args.address === 'number')
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
                            script: {
                                type: 'string',
                                description: 'script',
                            }
                        },
                        required: ['script'],
                    },
                },
                {
                    name: 'run_ida_command_filebased',
                    description: '(FOR IDE USAGE) Execute an IDA Pro Script (IdaPython, Version IDA 8.3)',
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
                    name: 'search_in_names',
                    description: 'Search for names/symbols in the binary',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            pattern: {
                                type: 'string',
                                description: 'Pattern to search for in names',
                            },
                            caseSensitive: {
                                type: 'boolean',
                                description: 'Whether the search is case sensitive (default: false)',
                            },
                            type: {
                                type: 'string',
                                description: 'Type of names to search for (function, data, import, export, label, all)',
                            },
                        },
                        required: ['pattern'],
                    },
                },
                {
                    name: 'get_xrefs_to',
                    description: 'Get cross-references to an address',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            address: {
                                type: 'string',
                                description: 'Target address to find references to',
                            },
                            type: {
                                type: 'string',
                                description: 'Type of references to find (code, data, all)',
                            },
                        },
                        required: ['address'],
                    },
                },
                {
                    name: 'get_xrefs_from',
                    description: 'Get cross-references from an address',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            address: {
                                type: 'string',
                                description: 'Source address to find references from',
                            },
                            type: {
                                type: 'string',
                                description: 'Type of references to find (code, data, all)',
                            },
                        },
                        required: ['address'],
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
                            'Invalid run IDA command arguments'
                        );
                    }

                    try {
                        const { script } = request.params.arguments;

                        let result = await ida.executeScript(script);

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
                                    text: `Found ${result.count} occurrences of immediate value ${value}:\n\n${JSON.stringify(result.results, null, 2)
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

                        /*const result = await ida.searchForText(text, {
                            caseSensitive,
                            startAddress,
                            endAddress
                        });*/


                        await client.connect();
                        db = client.db(dbName); collection = db.collection("strings");
                        let searchFor = "lua";
                        let newRegex = new RegExp(text, "i");
                        collection = db.collection("strings");
                        let res = await collection.find({
                            "TEXT": newRegex
                        })

                        let result = await res.toArray()

                        let result_count = result.length;
                        let result_str = "";
                        for (let i = 0; i < result.length; i++) {
                            result_str += ` ${result[i].MEMORY_ADDR}  ${result[i].TEXT} \n`
                        }
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Found ${result_count} \n\n ${result_str}`,
                                },
                            ],
                        }

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
                    break;
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
                                    text: `Found ${result.count} occurrences of byte sequence "${bytes}":\n\n${JSON.stringify(result.results, null, 2)
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

                        if (startAddress && typeof startAddress == 'string') {
                            startAddress.replace("00007", "0x7")
                        }
                        if (endAddress && typeof endAddress == 'string') {
                            endAddress.replace("00007", "0x7")
                        }


                        const result = await ida.getDisassembly(startAddress, {
                            endAddress,
                            count
                        });

                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Disassembly from ${result.start_address}${result.end_address ? ` to ${result.end_address}` : ''}:\n\n${JSON.stringify(result.disassembly, null, 2)
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
                                    text: `Retrieved ${result.count} functions from the binary:\n\n${JSON.stringify(result.functions, null, 2)
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
                                    text: `Retrieved ${result.count} exports from the binary:\n\n${JSON.stringify(result.exports, null, 2)
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
                                    text: `Retrieved ${result.count} strings from the binary:\n\n${JSON.stringify(result.strings, null, 2)
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

                case 'search_in_names':
                    if (!isValidSearchInNamesArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid search in names arguments'
                        );
                    }

                    try {
                        const { pattern, caseSensitive, type } = request.params.arguments;

                        const result = await ida.searchInNames(pattern, {
                            caseSensitive,
                            type: type as 'function' | 'data' | 'import' | 'export' | 'label' | 'all'
                        });

                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Found ${result.count} names matching "${pattern}":\n\n${JSON.stringify(result.results, null, 2)
                                        }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error searching in names: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'get_xrefs_to':
                    if (!isValidGetXrefsToArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid get xrefs to arguments'
                        );
                    }

                    try {
                        const { address, type } = request.params.arguments;

                        const result = await ida.getXrefsTo(address, {
                            type: type as 'code' | 'data' | 'all'
                        });

                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Found ${result.count} references to ${result.address} (${result.name}):\n\n${JSON.stringify(result.xrefs, null, 2)
                                        }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error getting xrefs to address: ${error.message || error}`,
                                },
                            ],
                            isError: true,
                        };
                    }

                case 'get_xrefs_from':
                    if (!isValidGetXrefsFromArgs(request.params.arguments)) {
                        throw new McpError(
                            ErrorCode.InvalidParams,
                            'Invalid get xrefs from arguments'
                        );
                    }

                    try {
                        const { address, type } = request.params.arguments;

                        const result = await ida.getXrefsFrom(address, {
                            type: type as 'code' | 'data' | 'all'
                        });

                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Found ${result.count} references from ${result.address} (${result.name}):\n\n${JSON.stringify(result.xrefs, null, 2)
                                        }`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Error getting xrefs from address: ${error.message || error}`,
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