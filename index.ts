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
}

const isValidRunIdaArgs = (args: any): args is RunIdaCommandArgs => {
    return (
        typeof args === 'object' &&
        args !== null &&
        (typeof args.scriptPath === 'string')
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
            ],
        }));



        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {

            if (request.params.name !== 'run_ida_command') {
                throw new McpError(
                    ErrorCode.MethodNotFound,
                    `Unknown tool: ${request.params.name}`
                );
            }

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

                let resul = await ida.executeScriptByPath(scriptPath);

                if (resul.error) {
                    return {
                        content: [
                            {
                                type: 'text',
                                text: `Error executing IDA Pro script: ${resul.error}`,
                            },
                        ],
                        isError: true,
                    };
                }
                if (outputPath && typeof outputPath === 'string') {
                    writeFileSync(outputPath, resul.output);
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
                            text: `IDA Pro Script Execution Results:\n\n${resul.output}`,
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