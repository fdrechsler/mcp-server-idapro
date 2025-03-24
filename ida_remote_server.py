"""
IDA Pro Remote Control Plugin

This plugin creates an HTTP server to remotely control certain IDA functions.
It exposes endpoints for executing scripts, getting strings, imports, exports, and functions.

Author: Florian Drechsler (@fdrechsler) fd@fdrechsler.com
"""

import idaapi
import idautils
import idc
import ida_funcs
import ida_bytes
import ida_nalt
import ida_name
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import socket
import ssl
import base64
import traceback
from urllib.parse import parse_qs, urlparse
import time

# Default settings
DEFAULT_HOST = "127.0.0.1"  # Localhost only for security
DEFAULT_PORT = 9045  
PLUGIN_NAME = "IDA Pro Remote Control"
PLUGIN_VERSION = "1.0.0"
AUTO_START = True  # Automatically start server on plugin load

# Global variables
g_server = None
g_server_thread = None

# Synchronization flags for execute_sync
MFF_FAST = 0x0  # Execute as soon as possible
MFF_READ = 0x1  # Wait for the database to be read-ready
MFF_WRITE = 0x2  # Wait for the database to be write-ready

class RemoteControlHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the IDA Pro remote control plugin."""
    
    # Add timeout for HTTP requests
    timeout = 60  # 60-second timeout for HTTP requests
    
    def log_message(self, format, *args):
        """Override logging to use IDA's console."""
        print(f"[RemoteControl] {format % args}")
    
    def _send_response(self, status_code, content_type, content):
        """Helper method to send HTTP response."""
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        except (ConnectionResetError, BrokenPipeError, socket.error) as e:
            print(f"[RemoteControl] Connection error when sending response: {e}")
    
    def _send_json_response(self, data, status_code=200):
        """Helper method to send JSON response."""
        try:
            content = json.dumps(data).encode('utf-8')
            self._send_response(status_code, 'application/json', content)
        except Exception as e:
            print(f"[RemoteControl] Error preparing JSON response: {e}")
            # Try to send a simplified error response
            try:
                simple_error = json.dumps({'error': 'Internal server error'}).encode('utf-8')
                self._send_response(500, 'application/json', simple_error)
            except:
                # Silently fail if we can't even send the error
                pass
    
    def _send_error_response(self, message, status_code=400):
        """Helper method to send error response."""
        self._send_json_response({'error': message}, status_code)
    
    def _parse_post_data(self):
        """Parse POST data from request."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Handle different content types
        content_type = self.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            return json.loads(post_data)
        elif 'application/x-www-form-urlencoded' in content_type:
            parsed_data = parse_qs(post_data)
            # Convert lists to single values where appropriate
            return {k: v[0] if len(v) == 1 else v for k, v in parsed_data.items()}
        else:
            return {'raw_data': post_data}
    
    def do_GET(self):
        """Handle GET requests."""
        path = self.path.lower()
        
        try:
            if path == '/api/info':
                self._handle_info()
            elif path == '/api/strings':
                self._handle_get_strings()
            elif path == '/api/exports':
                self._handle_get_exports()
            elif path == '/api/imports':
                self._handle_get_imports()
            elif path == '/api/functions':
                self._handle_get_functions()
            elif path.startswith('/api/search/immediate'):
                self._handle_search_immediate()
            elif path.startswith('/api/search/text'):
                self._handle_search_text()
            elif path.startswith('/api/search/bytes'):
                self._handle_search_bytes()
            elif path.startswith('/api/disassembly'):
                self._handle_get_disassembly()
            else:
                self._send_error_response('Endpoint not found', 404)
        except Exception as e:
            error_msg = f"Error processing request: {str(e)}\n{traceback.format_exc()}"
            print(f"[RemoteControl] {error_msg}")
            self._send_error_response(error_msg, 500)
    
    def do_POST(self):
        """Handle POST requests."""
        path = self.path.lower()
        
        try:
            if path == '/api/execute':
                self._handle_execute_script()
            elif path == '/api/executebypath':
                self._handle_execute_by_path()
            elif path == '/api/executebody':
                self._handle_execute_body()
            else:
                self._send_error_response('Endpoint not found', 404)
        except Exception as e:
            error_msg = f"Error processing request: {str(e)}\n{traceback.format_exc()}"
            print(f"[RemoteControl] {error_msg}")
            self._send_error_response(error_msg, 500)
    
    def _handle_info(self):
        """Handle info request."""
        result = self._execute_in_main_thread(self._get_info_impl)
        self._send_json_response(result)
    
    def _get_info_impl(self):
        """Implementation of getting info - runs in main thread."""
        info = {
            'plugin_name': PLUGIN_NAME,
            'plugin_version': PLUGIN_VERSION,
            'ida_version': idaapi.get_kernel_version(),
            'file_name': idaapi.get_input_file_path(),
            'endpoints': [
                {'path': '/api/info', 'method': 'GET', 'description': 'Get plugin information'},
                {'path': '/api/strings', 'method': 'GET', 'description': 'Get strings from binary'},
                {'path': '/api/exports', 'method': 'GET', 'description': 'Get exports from binary'},
                {'path': '/api/imports', 'method': 'GET', 'description': 'Get imports from binary'},
                {'path': '/api/functions', 'method': 'GET', 'description': 'Get function list'},
                {'path': '/api/search/immediate', 'method': 'GET', 'description': 'Search for immediate values'},
                {'path': '/api/search/text', 'method': 'GET', 'description': 'Search for text in binary'},
                {'path': '/api/search/bytes', 'method': 'GET', 'description': 'Search for byte sequence'},
                {'path': '/api/disassembly', 'method': 'GET', 'description': 'Get disassembly for an address range'},
                {'path': '/api/execute', 'method': 'POST', 'description': 'Execute Python script (JSON/Form)'},
                {'path': '/api/executebypath', 'method': 'POST', 'description': 'Execute Python script from file path'},
                {'path': '/api/executebody', 'method': 'POST', 'description': 'Execute Python script from raw body'},
            ]
        }
        return info
    
    def _handle_execute_script(self):
        """Handle script execution request."""
        post_data = self._parse_post_data()
        
        if 'script' not in post_data:
            self._send_error_response('No script provided')
            return
        
        script = post_data['script']
        
        # Execute script in the main thread
        result = self._execute_in_main_thread(self._execute_script_impl, script)
        
        if 'error' in result:
            self._send_error_response(result['error'], 500)
        else:
            self._send_json_response(result)
    
    def _handle_execute_by_path(self):
        """Handle script execution from a file path."""
        post_data = self._parse_post_data()
        
        if 'path' not in post_data:
            self._send_error_response('No script path provided')
            return
        
        script_path = post_data['path']
        
        try:
            # Use IDA's main thread to read the file
            def read_script_file():
                try:
                    with open(script_path, 'r') as f:
                        return {'script': f.read()}
                except Exception as e:
                    return {'error': f"Could not read script file: {str(e)}"}
            
            file_result = self._execute_in_main_thread(read_script_file)
            
            if 'error' in file_result:
                self._send_error_response(file_result['error'], 400)
                return
            
            script = file_result['script']
            
            # Execute the script using our existing method
            result = self._execute_in_main_thread(self._execute_script_impl, script)
            
            if 'error' in result:
                self._send_error_response(result['error'], 500)
            else:
                self._send_json_response(result)
        
        except Exception as e:
            error_msg = f"Error executing script from path: {str(e)}\n{traceback.format_exc()}"
            print(f"[RemoteControl] {error_msg}")
            self._send_error_response(error_msg, 500)
    
    def _handle_execute_body(self):
        """Handle script execution from raw body content."""
        try:
            # Read raw body content
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 1000000:  # 1MB limit
                self._send_error_response('Script too large (>1MB)', 413)
                return
                
            script = self.rfile.read(content_length).decode('utf-8')
            
            # Execute the script using our existing method
            result = self._execute_in_main_thread(self._execute_script_impl, script)
            
            if 'error' in result:
                self._send_error_response(result['error'], 500)
            else:
                self._send_json_response(result)
        
        except Exception as e:
            error_msg = f"Error executing script from body: {str(e)}\n{traceback.format_exc()}"
            print(f"[RemoteControl] {error_msg}")
            self._send_error_response(error_msg, 500)
    
    def _execute_script_impl(self, script):
        """Implementation of script execution - runs in main thread with safety measures."""
        # Create a safe execution environment with IDA modules
        exec_globals = {
            'idaapi': idaapi,
            'idautils': idautils,
            'idc': idc,
            'ida_funcs': ida_funcs,
            'ida_bytes': ida_bytes,
            'ida_nalt': ida_nalt,
            'ida_name': ida_name,
        }
        
        # Redirect stdout to capture output
        import io
        import sys
        import signal
        
        original_stdout = sys.stdout
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        # Create hooks to automatically respond to IDA prompts
        original_funcs = {}
        
        # Store original functions we're going to override
        original_funcs['ask_yn'] = idaapi.ask_yn
        original_funcs['ask_buttons'] = idaapi.ask_buttons
        original_funcs['ask_text'] = idaapi.ask_text
        original_funcs['ask_str'] = idaapi.ask_str
        original_funcs['ask_file'] = idaapi.ask_file
        original_funcs['display_copyright_warning'] = idaapi.display_copyright_warning
        
        # Also handle lower-level IDA UI functions
        if hasattr(idaapi, "get_kernel_version") and idaapi.get_kernel_version() >= "7.0":
            # IDA 7+ has these functions
            if hasattr(idaapi, "warning"):
                original_funcs['warning'] = idaapi.warning
                idaapi.warning = lambda *args, **kwargs: print(f"[AUTO-CONFIRM] Warning suppressed: {args}")
                
            if hasattr(idaapi, "info"):
                original_funcs['info'] = idaapi.info
                idaapi.info = lambda *args, **kwargs: print(f"[AUTO-CONFIRM] Info suppressed: {args}")
            
            # For specific known dialogs like the "bad digit" dialog
            if hasattr(idc, "set_inf_attr"):
                # Suppress "bad digit" dialogs with this setting
                original_funcs['INFFL_ALLASM'] = idc.get_inf_attr(idc.INF_AF)
                idc.set_inf_attr(idc.INF_AF, idc.get_inf_attr(idc.INF_AF) | 0x2000)  # Set INFFL_ALLASM flag
                
        # Create a UI hook to capture any other dialogs
        class DialogHook(idaapi.UI_Hooks):
            def populating_widget_popup(self, widget, popup):
                # Just suppress all popups
                print("[AUTO-CONFIRM] Suppressing popup")
                return 1
                
            def finish_populating_widget_popup(self, widget, popup):
                # Also suppress here
                print("[AUTO-CONFIRM] Suppressing popup finish")
                return 1
                
            def ready_to_run(self):
                # Always continue
                return 1
                
            def updating_actions(self, ctx):
                # Always continue
                return 1
                
            def updated_actions(self):
                # Always continue
                return 1
                
            def ui_refresh(self, cnd):
                # Suppress UI refreshes
                return 1

        # Install UI hook
        ui_hook = DialogHook()
        ui_hook.hook()
        
        # Functions to automatically respond to various prompts
        def auto_yes_no(*args, **kwargs):
            print(f"[AUTO-CONFIRM] Prompt intercepted (Yes/No): {args}")
            return idaapi.ASKBTN_YES  # Always respond YES
            
        def auto_buttons(*args, **kwargs):
            print(f"[AUTO-CONFIRM] Prompt intercepted (Buttons): {args}")
            return 0  # Return first button (usually OK/Yes/Continue)
            
        def auto_text(*args, **kwargs):
            print(f"[AUTO-CONFIRM] Prompt intercepted (Text): {args}")
            return ""  # Return empty string
            
        def auto_file(*args, **kwargs):
            print(f"[AUTO-CONFIRM] Prompt intercepted (File): {args}")
            return ""  # Return empty string
            
        def auto_ignore(*args, **kwargs):
            print(f"[AUTO-CONFIRM] Warning intercepted: {args}")
            return 0  # Just return something
        
        # Override IDA's prompt functions with our auto-response versions
        idaapi.ask_yn = auto_yes_no
        idaapi.ask_buttons = auto_buttons
        idaapi.ask_text = auto_text
        idaapi.ask_str = auto_text
        idaapi.ask_file = auto_file
        idaapi.display_copyright_warning = auto_ignore
        
        # IMPORTANT: Also override searching functions with safer versions
        # The "Bad digit" dialog is often triggered by these
        if hasattr(idc, "find_binary"):
            original_funcs['find_binary'] = idc.find_binary
            def safe_find_binary(ea, flag, searchstr, radix=16):
                # Always treat as a string by adding quotes if not present
                if '"' not in searchstr and "'" not in searchstr:
                    searchstr = f'"{searchstr}"'
                print(f"[AUTO-CONFIRM] Making search safe: {searchstr}")
                return original_funcs['find_binary'](ea, flag, searchstr, radix)
            idc.find_binary = safe_find_binary
            
        # Set batch mode to minimize UI interactions (stronger settings)
        orig_batch = idaapi.set_script_timeout(1)  # Set script timeout to suppress dialogs
        
        # Additional batch mode settings
        orig_user_screen_ea = idaapi.get_screen_ea()
        
        # Save current IDA settings
        try:
            # Enable batch mode if available
            if hasattr(idaapi, "batch_mode_enabled"):
                original_funcs['batch_mode'] = idaapi.batch_mode_enabled()
                idaapi.enable_batch_mode(True)
            
            # Disable analysis wait box
            if hasattr(idaapi, "set_flag"):
                idaapi.set_flag(idaapi.SW_SHHID_ITEM, True)  # Hide wait dialogs
                idaapi.set_flag(idaapi.SW_HIDE_UNDEF, True)  # Hide undefined items
                idaapi.set_flag(idaapi.SW_HIDE_SEGADDRS, True)  # Hide segment addressing
                
            # For newer versions of IDA
            if hasattr(idc, "batch"):
                original_funcs['batch_mode_idc'] = idc.batch(1)  # Enable batch mode
        
        except Exception as e:
            print(f"[AUTO-CONFIRM] Error setting batch mode: {e}")
        
        # Script timeout handling
        class TimeoutException(Exception):
            pass
            
        def timeout_handler(signum, frame):
            raise TimeoutException("Script execution timed out")
        
        # Set timeout for script execution (10 seconds)
        old_handler = None
        try:
            # Only set alarm on platforms that support it (not Windows)
            if hasattr(signal, 'SIGALRM'):
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(10)  # 10 second timeout
        except (AttributeError, ValueError):
            # Signal module might not have SIGALRM on Windows
            pass
            
        try:
            # Execute the script with size limit to prevent memory issues
            if len(script) > 1000000:  # 1MB limit
                return {'error': 'Script too large (>1MB)'}
                
            # Execute the script
            exec(script, exec_globals)
            output = captured_output.getvalue()
            
            # Get return value if set
            return_value = exec_globals.get('return_value', None)
            
            response = {
                'success': True,
                'output': output[:1000000]  # Limit output size to 1MB
            }
            
            if return_value is not None:
                try:
                    # Try to serialize return_value to JSON with size limit
                    json_str = json.dumps(return_value)
                    if len(json_str) <= 1000000:  # 1MB limit
                        response['return_value'] = return_value
                    else:
                        response['return_value'] = str(return_value)[:1000000] + "... (truncated)"
                except (TypeError, OverflowError):
                    # If not JSON serializable, convert to string with limit
                    response['return_value'] = str(return_value)[:1000000] + (
                        "... (truncated)" if len(str(return_value)) > 1000000 else "")
            
            return response
            
        except TimeoutException:
            error_msg = "Script execution timed out (exceeded 10 seconds)"
            print(f"[RemoteControl] {error_msg}")
            return {'error': error_msg}
        except MemoryError:
            error_msg = "Script caused a memory error"
            print(f"[RemoteControl] {error_msg}")
            return {'error': error_msg}
        except Exception as e:
            error_msg = f"Script execution error: {str(e)}\n{traceback.format_exc()}"
            print(f"[RemoteControl] {error_msg}")
            return {'error': error_msg}
        finally:
            # Restore stdout
            sys.stdout = original_stdout
            
            # Restore original IDA functions
            for func_name, original_func in original_funcs.items():
                # Special case for INFFL_ALLASM flag
                if func_name == 'INFFL_ALLASM':
                    idc.set_inf_attr(idc.INF_AF, original_func)
                # Special case for batch mode
                elif func_name == 'batch_mode':
                    if hasattr(idaapi, "enable_batch_mode"):
                        idaapi.enable_batch_mode(original_func)
                elif func_name == 'batch_mode_idc':
                    if hasattr(idc, "batch"):
                        idc.batch(original_func)
                else:
                    # For all other functions
                    try:
                        if hasattr(idaapi, func_name):
                            setattr(idaapi, func_name, original_func)
                        elif hasattr(idc, func_name):
                            setattr(idc, func_name, original_func)
                    except:
                        print(f"[RemoteControl] Failed to restore {func_name}")
            
            # Restore screen position
            idaapi.jumpto(orig_user_screen_ea)
            
            # Unhook UI hooks
            ui_hook.unhook()
            
            # Restore original batch mode
            idaapi.set_script_timeout(orig_batch)
            
            # Cancel alarm if set (for non-Windows platforms)
            try:
                if hasattr(signal, 'SIGALRM'):
                    signal.alarm(0)
                    if old_handler is not None:
                        signal.signal(signal.SIGALRM, old_handler)
            except (AttributeError, ValueError, UnboundLocalError):
                pass
    
    def _handle_get_strings(self):
        """Handle get strings request."""
        result = self._execute_in_main_thread(self._get_strings_impl)
        self._send_json_response(result)
    
    def _get_strings_impl(self):
        """Implementation of getting strings - runs in main thread."""
        min_length = 4  # Minimum string length to include
        strings_list = []
        
        # Get all strings from binary
        for ea in idautils.Strings():
            if ea.length >= min_length:
                string_value = str(ea)
                string_address = ea.ea
                string_info = {
                    'address': f"0x{string_address:X}",
                    'value': string_value,
                    'length': ea.length,
                    'type': 'pascal' if ea.strtype == 1 else 'c'
                }
                strings_list.append(string_info)
        
        return {
            'count': len(strings_list),
            'strings': strings_list
        }
    
    def _handle_get_exports(self):
        """Handle get exports request."""
        result = self._execute_in_main_thread(self._get_exports_impl)
        self._send_json_response(result)
    
    def _get_exports_impl(self):
        """Implementation of getting exports - runs in main thread."""
        exports_list = []
        
        # Process exports
        for ordinal, ea, name in idautils.Entries():
            exports_list.append({
                'address': f"0x{ea:X}",
                'name': name,
                'ordinal': ordinal
            })
        
        return {
            'count': len(exports_list),
            'exports': exports_list
        }
    
    def _handle_get_imports(self):
        """Handle get imports request."""
        result = self._execute_in_main_thread(self._get_imports_impl)
        self._send_json_response(result)
    
    def _get_imports_impl(self):
        """Implementation of getting imports - runs in main thread."""
        imports_list = []
        
        # Process imports
        nimps = ida_nalt.get_import_module_qty()
        for i in range(0, nimps):
            name = ida_nalt.get_import_module_name(i)
            if not name:
                continue
            
            def imp_cb(ea, name, ordinal):
                if name:
                    imports_list.append({
                        'address': f"0x{ea:X}",
                        'name': name,
                        'ordinal': ordinal
                    })
                return True
            
            ida_nalt.enum_import_names(i, imp_cb)
        
        return {
            'count': len(imports_list),
            'imports': imports_list
        }
    
    def _handle_get_functions(self):
        """Handle get functions request."""
        result = self._execute_in_main_thread(self._get_functions_impl)
        self._send_json_response(result)
    
    def _get_functions_impl(self):
        """Implementation of getting functions - runs in main thread."""
        functions_list = []
        
        # Get all functions
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            if func:
                func_name = ida_name.get_ea_name(ea)
                function_info = {
                    'address': f"0x{ea:X}",
                    'name': func_name,
                    'size': func.size(),
                    'start': f"0x{func.start_ea:X}",
                    'end': f"0x{func.end_ea:X}",
                    'flags': func.flags
                }
                functions_list.append(function_info)
        
        return {
            'count': len(functions_list),
            'functions': functions_list
        }
        
    def _handle_search_immediate(self):
        """Handle search for immediate value request."""
        # Parse query parameters
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        
        # Get parameters with defaults
        value = params.get('value', [''])[0]
        if not value:
            self._send_error_response('Missing required parameter: value')
            return
            
        # Optional parameters
        try:
            radix = int(params.get('radix', ['16'])[0])
        except ValueError:
            radix = 16
            
        try:
            start_ea = int(params.get('start', ['0'])[0], 0)
        except ValueError:
            start_ea = 0
            
        try:
            end_ea = int(params.get('end', ['0'])[0], 0)
        except ValueError:
            end_ea = idc.BADADDR
            
        # Execute search in main thread
        result = self._execute_in_main_thread(
            self._search_immediate_impl,
            value,
            radix,
            start_ea,
            end_ea
        )
        self._send_json_response(result)
    
    def _search_immediate_impl(self, value, radix, start_ea, end_ea):
        """Implementation of searching for immediate values - runs in main thread."""
        results = []
        
        try:
            # Convert value to integer if it's a number
            if isinstance(value, str) and value.isdigit():
                value = int(value, radix)
                
            # Search for immediate values
            for ea in idautils.Functions():
                func = ida_funcs.get_func(ea)
                if not func:
                    continue
                    
                # Skip if outside specified range
                if start_ea > 0 and func.start_ea < start_ea:
                    continue
                if end_ea > 0 and func.start_ea >= end_ea:
                    continue
                
                # Iterate through instructions in the function
                current_ea = func.start_ea
                while current_ea < func.end_ea:
                    insn = idaapi.insn_t()
                    insn_len = idaapi.decode_insn(insn, current_ea)
                    if insn_len > 0:
                        # Check operands for immediate values
                        for i in range(len(insn.ops)):
                            op = insn.ops[i]
                            if op.type == idaapi.o_imm:
                                # If searching for a specific value
                                if isinstance(value, int) and op.value == value:
                                    disasm = idc.generate_disasm_line(current_ea, 0)
                                    results.append({
                                        'address': f"0x{current_ea:X}",
                                        'instruction': disasm,
                                        'value': op.value,
                                        'operand_index': i
                                    })
                                # If searching for a string pattern in the disassembly
                                elif isinstance(value, str) and value in idc.generate_disasm_line(current_ea, 0):
                                    disasm = idc.generate_disasm_line(current_ea, 0)
                                    results.append({
                                        'address': f"0x{current_ea:X}",
                                        'instruction': disasm,
                                        'value': op.value,
                                        'operand_index': i
                                    })
                        current_ea += insn_len
                    else:
                        current_ea += 1
        except Exception as e:
            return {'error': f"Error searching for immediate values: {str(e)}"}
            
        return {
            'count': len(results),
            'results': results
        }
    
    def _handle_search_text(self):
        """Handle search for text request."""
        # Parse query parameters
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        
        # Get parameters with defaults
        text = params.get('text', [''])[0]
        if not text:
            self._send_error_response('Missing required parameter: text')
            return
            
        # Optional parameters
        try:
            start_ea = int(params.get('start', ['0'])[0], 0)
        except ValueError:
            start_ea = 0
            
        try:
            end_ea = int(params.get('end', ['0'])[0], 0)
        except ValueError:
            end_ea = idc.BADADDR
            
        case_sensitive = params.get('case_sensitive', ['false'])[0].lower() == 'true'
        
        # Execute search in main thread
        result = self._execute_in_main_thread(
            self._search_text_impl,
            text,
            case_sensitive,
            start_ea,
            end_ea
        )
        self._send_json_response(result)
    
    def _search_text_impl(self, text, case_sensitive, start_ea, end_ea):
        """Implementation of searching for text - runs in main thread."""
        results = []
        
        try:
            # Get all strings from binary
            for string_item in idautils.Strings():
                if string_item.ea < start_ea:
                    continue
                if end_ea > 0 and string_item.ea >= end_ea:
                    continue
                    
                string_value = str(string_item)
                
                # Check if text is in string
                if (case_sensitive and text in string_value) or \
                   (not case_sensitive and text.lower() in string_value.lower()):
                    results.append({
                        'address': f"0x{string_item.ea:X}",
                        'value': string_value,
                        'length': string_item.length,
                        'type': 'pascal' if string_item.strtype == 1 else 'c'
                    })
        except Exception as e:
            return {'error': f"Error searching for text: {str(e)}"}
            
        return {
            'count': len(results),
            'results': results
        }
    
    def _handle_search_bytes(self):
        """Handle search for byte sequence request."""
        # Parse query parameters
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        
        # Get parameters with defaults
        byte_str = params.get('bytes', [''])[0]
        if not byte_str:
            self._send_error_response('Missing required parameter: bytes')
            return
            
        # Optional parameters
        try:
            start_ea = int(params.get('start', ['0'])[0], 0)
        except ValueError:
            start_ea = 0
            
        try:
            end_ea = int(params.get('end', ['0'])[0], 0)
        except ValueError:
            end_ea = idc.BADADDR
            
        # Execute search in main thread
        result = self._execute_in_main_thread(
            self._search_bytes_impl,
            byte_str,
            start_ea,
            end_ea
        )
        self._send_json_response(result)
    
    def _search_bytes_impl(self, byte_str, start_ea, end_ea):
        """Implementation of searching for byte sequence - runs in main thread."""
        results = []
        
        try:
            # Ensure byte_str is properly formatted for IDA's find_binary
            # IDA expects a string like "41 42 43" or "41 ?? 43" where ?? is a wildcard
            # Clean up the input to ensure it's in the right format
            byte_str = byte_str.strip()
            if not byte_str.startswith('"') and not byte_str.startswith("'"):
                byte_str = f'"{byte_str}"'
            
            # Start searching
            ea = start_ea
            while ea != idc.BADADDR:
                ea = idc.find_binary(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT, byte_str)
                if ea == idc.BADADDR or (end_ea > 0 and ea >= end_ea):
                    break
                    
                # Get some context around the found bytes
                disasm = idc.generate_disasm_line(ea, 0)
                
                # Add to results
                results.append({
                    'address': f"0x{ea:X}",
                    'disassembly': disasm,
                    'bytes': ' '.join([f"{idc.get_wide_byte(ea + i):02X}" for i in range(8)])  # Show 8 bytes
                })
                
                # Move to next byte to continue search
                ea += 1
        except Exception as e:
            return {'error': f"Error searching for byte sequence: {str(e)}"}
            
        return {
            'count': len(results),
            'results': results
        }
    
    def _handle_get_disassembly(self):
        """Handle get disassembly request."""
        # Parse query parameters
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        
        # Get parameters with defaults
        try:
            start_ea = int(params.get('start', ['0'])[0], 0)
        except ValueError:
            self._send_error_response('Invalid start address')
            return
            
        # Optional parameters
        try:
            end_ea = int(params.get('end', ['0'])[0], 0)
        except ValueError:
            end_ea = 0
            
        try:
            count = int(params.get('count', ['10'])[0])
        except ValueError:
            count = 10
            
        # Execute in main thread
        result = self._execute_in_main_thread(
            self._get_disassembly_impl,
            start_ea,
            end_ea,
            count
        )
        self._send_json_response(result)
    
    def _get_disassembly_impl(self, start_ea, end_ea, count):
        """Implementation of getting disassembly - runs in main thread."""
        disassembly = []
        
        try:
            # If end_ea is specified, use it, otherwise use count
            if end_ea > 0:
                current_ea = start_ea
                while current_ea < end_ea:
                    disasm = idc.generate_disasm_line(current_ea, 0)
                    bytes_str = ' '.join([f"{idc.get_wide_byte(current_ea + i):02X}" for i in range(min(16, idc.get_item_size(current_ea)))])
                    
                    disassembly.append({
                        'address': f"0x{current_ea:X}",
                        'disassembly': disasm,
                        'bytes': bytes_str,
                        'size': idc.get_item_size(current_ea)
                    })
                    
                    current_ea += idc.get_item_size(current_ea)
                    if len(disassembly) >= 1000:  # Limit to 1000 instructions for safety
                        break
            else:
                # Use count to limit the number of instructions
                current_ea = start_ea
                for _ in range(min(count, 1000)):  # Limit to 1000 instructions for safety
                    disasm = idc.generate_disasm_line(current_ea, 0)
                    bytes_str = ' '.join([f"{idc.get_wide_byte(current_ea + i):02X}" for i in range(min(16, idc.get_item_size(current_ea)))])
                    
                    disassembly.append({
                        'address': f"0x{current_ea:X}",
                        'disassembly': disasm,
                        'bytes': bytes_str,
                        'size': idc.get_item_size(current_ea)
                    })
                    
                    current_ea += idc.get_item_size(current_ea)
                    if current_ea == idc.BADADDR:
                        break
        except Exception as e:
            return {'error': f"Error getting disassembly: {str(e)}"}
            
        return {
            'count': len(disassembly),
            'disassembly': disassembly,
            'start_address': f"0x{start_ea:X}",
            'end_address': f"0x{end_ea:X}" if end_ea > 0 else None
        }
    
    def _execute_in_main_thread(self, func, *args, **kwargs):
        """Execute a function in the main thread with additional safeguards."""
        result_container = {}
        execution_done = threading.Event()
        
        def sync_wrapper():
            """Wrapper function to capture the result safely."""
            try:
                result_container['result'] = func(*args, **kwargs)
            except Exception as e:
                result_container['error'] = str(e)
                result_container['traceback'] = traceback.format_exc()
            finally:
                # Signal that execution has finished
                execution_done.set()
            return 0  # Must return an integer
        
        # Schedule execution in the main thread
        idaapi.execute_sync(sync_wrapper, MFF_READ)
        
        # Wait for the result with a timeout
        max_wait = 30  # Maximum wait time in seconds
        if not execution_done.wait(max_wait):
            error_msg = f"Operation timed out after {max_wait} seconds"
            print(f"[RemoteControl] {error_msg}")
            return {'error': error_msg}
        
        if 'error' in result_container:
            print(f"[RemoteControl] Error in main thread: {result_container['error']}")
            print(result_container.get('traceback', ''))
            return {'error': result_container['error']}
        
        return result_container.get('result', {'error': 'Unknown error occurred'})


class RemoteControlServer:
    """HTTP server for IDA Pro remote control."""
    
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.running = False
    
    def start(self):
        """Start the HTTP server."""
        if self.running:
            print("[RemoteControl] Server is already running")
            return False
        
        try:
            self.server = HTTPServer((self.host, self.port), RemoteControlHandler)
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.running = True
            print(f"[RemoteControl] Server started on http://{self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[RemoteControl] Failed to start server: {str(e)}")
            return False
    
    def stop(self):
        """Stop the HTTP server."""
        if not self.running:
            print("[RemoteControl] Server is not running")
            return False
        
        try:
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join()
            self.running = False
            print("[RemoteControl] Server stopped")
            return True
        except Exception as e:
            print(f"[RemoteControl] Failed to stop server: {str(e)}")
            return False
    
    def is_running(self):
        """Check if the server is running."""
        return self.running


class RemoteControlPlugin(idaapi.plugin_t):
    """IDA Pro plugin for remote control."""
    
    flags = idaapi.PLUGIN_KEEP
    comment = "Remote control for IDA through HTTP"
    help = "Provides HTTP endpoints to control IDA Pro remotely"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Alt-R"
    
    def init(self):
        """Initialize the plugin."""
        print(f"[{PLUGIN_NAME}] Initializing...")
        
        # Auto-start server if configured
        if AUTO_START:
            global g_server
            g_server = RemoteControlServer(DEFAULT_HOST, DEFAULT_PORT)
            success = g_server.start()
            
            if success:
                print(f"[{PLUGIN_NAME}] Server auto-started on http://{DEFAULT_HOST}:{DEFAULT_PORT}")
                print(f"[{PLUGIN_NAME}] Available endpoints:")
           
            else:
                g_server = None
                print(f"[{PLUGIN_NAME}] Failed to auto-start server")
        
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        """Run the plugin when activated manually."""
        global g_server
        
        # Check if server is already running
        if g_server and g_server.is_running():
            response = idaapi.ask_yn(idaapi.ASKBTN_NO, 
                                     "Remote control server is already running.\nDo you want to stop it?")
            if response == idaapi.ASKBTN_YES:
                g_server.stop()
                g_server = None
            return
        
        # If AUTO_START is enabled but server isn't running, start with default settings
        if AUTO_START:
            g_server = RemoteControlServer(DEFAULT_HOST, DEFAULT_PORT)
            success = g_server.start()
            
            if success:
                print(f"[{PLUGIN_NAME}] Server started on http://{DEFAULT_HOST}:{DEFAULT_PORT}")
             
            else:
                g_server = None
                print(f"[{PLUGIN_NAME}] Failed to start server")
            return
        
        # Manual configuration if AUTO_START is disabled
        # Get host and port from user
        host = idaapi.ask_str(DEFAULT_HOST, 0, "Enter host address (e.g. 127.0.0.1):")
        if not host:
            host = DEFAULT_HOST
        
        port_str = idaapi.ask_str(str(DEFAULT_PORT), 0, "Enter port number:")
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            port = DEFAULT_PORT
        
        # Start server
        g_server = RemoteControlServer(host, port)
        success = g_server.start()
        
        if success:
            print(f"[{PLUGIN_NAME}] Server started on http://{host}:{port}")
            print(f"[{PLUGIN_NAME}] Available endpoints:")
        
        else:
            g_server = None
            print(f"[{PLUGIN_NAME}] Failed to start server")
    
    def term(self):
        """Terminate the plugin."""
        global g_server
        
        if g_server and g_server.is_running():
            g_server.stop()
            g_server = None
        
        print(f"[{PLUGIN_NAME}] Plugin terminated")


# Register the plugin
def PLUGIN_ENTRY():
    """Return the plugin instance."""
    return RemoteControlPlugin()


# For testing/debugging in the script editor
if __name__ == "__main__":
    # This will only run when executed in the IDA script editor
    plugin = RemoteControlPlugin()
    plugin.run(0)