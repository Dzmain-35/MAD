"""
File Viewer and Executor Module for MAD (Malware Analysis Dashboard)
Provides built-in file viewing and extension-based execution capabilities.

Author: MAD Development Team
"""

import os
import subprocess
import threading
from typing import Optional, Tuple
from pathlib import Path


class FileViewerExecutor:
    """
    Handles file viewing (hex, text) and execution based on file extension.
    """

    def __init__(self):
        """Initialize the file viewer/executor."""
        self.execution_handlers = {
            '.py': self._execute_python,
            '.pyw': self._execute_python,
            '.ps1': self._execute_powershell,
            '.bat': self._execute_batch,
            '.cmd': self._execute_batch,
            '.exe': self._execute_binary,
            '.dll': self._execute_dll,
            '.js': self._execute_javascript,
            '.vbs': self._execute_vbscript,
            '.vbe': self._execute_vbscript,
            '.wsf': self._execute_wscript,
            '.hta': self._execute_hta,
        }

    def read_file_as_hex(self, file_path: str, max_bytes: int = 1024 * 1024) -> Tuple[str, int]:
        """
        Read file and return hex dump format.

        Args:
            file_path: Path to the file
            max_bytes: Maximum bytes to read (default 1MB)

        Returns:
            Tuple of (hex_dump_string, total_bytes_read)
        """
        hex_lines = []
        bytes_read = 0

        try:
            with open(file_path, 'rb') as f:
                while bytes_read < max_bytes:
                    chunk = f.read(16)  # Read 16 bytes at a time (one line)
                    if not chunk:
                        break

                    # Offset
                    offset = f"{bytes_read:08X}"

                    # Hex values
                    hex_values = ' '.join(f'{b:02X}' for b in chunk)
                    hex_values = hex_values.ljust(47)  # Pad to align ASCII

                    # ASCII representation
                    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

                    # Combine
                    hex_lines.append(f"{offset}  {hex_values}  {ascii_repr}")
                    bytes_read += len(chunk)

            return '\n'.join(hex_lines), bytes_read

        except Exception as e:
            return f"Error reading file: {str(e)}", 0

    def read_file_as_text(self, file_path: str, max_lines: int = 10000) -> Tuple[str, int]:
        """
        Read file as text.

        Args:
            file_path: Path to the file
            max_lines: Maximum lines to read

        Returns:
            Tuple of (text_content, lines_read)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        lines.append(f"\n... (truncated at {max_lines} lines)")
                        break
                    lines.append(line.rstrip('\n\r'))

                return '\n'.join(lines), len(lines)

        except Exception as e:
            # Try binary read if text fails
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 100)  # Read first 100KB
                    text = content.decode('utf-8', errors='replace')
                    return text, len(text.split('\n'))
            except:
                return f"Error reading file: {str(e)}", 0

    def can_execute(self, file_path: str) -> bool:
        """
        Check if file can be executed based on extension.

        Args:
            file_path: Path to the file

        Returns:
            True if file can be executed
        """
        ext = Path(file_path).suffix.lower()
        return ext in self.execution_handlers

    def execute_file(self, file_path: str, callback=None) -> Optional[dict]:
        """
        Execute file based on extension.

        Args:
            file_path: Path to the file to execute
            callback: Optional callback function to receive output

        Returns:
            Dictionary with execution info or None if cannot execute
        """
        if not os.path.exists(file_path):
            return {'error': 'File not found', 'success': False}

        ext = Path(file_path).suffix.lower()
        handler = self.execution_handlers.get(ext)

        if not handler:
            return {'error': f'No execution handler for {ext} files', 'success': False}

        try:
            # Execute in background thread
            result = {'success': False, 'output': '', 'error': ''}

            def run_execution():
                try:
                    output, error = handler(file_path)
                    result['success'] = True
                    result['output'] = output
                    result['error'] = error
                    if callback:
                        callback(result)
                except Exception as e:
                    result['success'] = False
                    result['error'] = str(e)
                    if callback:
                        callback(result)

            thread = threading.Thread(target=run_execution, daemon=True)
            thread.start()

            return {
                'success': True,
                'message': f'Executing {Path(file_path).name}...',
                'extension': ext,
                'thread': thread
            }

        except Exception as e:
            return {'error': str(e), 'success': False}

    def _execute_python(self, file_path: str) -> Tuple[str, str]:
        """Execute Python script."""
        try:
            result = subprocess.run(
                ['python', file_path],
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
                cwd=os.path.dirname(file_path)
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return '', 'Execution timed out after 30 seconds'
        except Exception as e:
            return '', f'Error executing Python script: {str(e)}'

    def _execute_powershell(self, file_path: str) -> Tuple[str, str]:
        """Execute PowerShell script."""
        try:
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-File', file_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(file_path)
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return '', 'Execution timed out after 30 seconds'
        except Exception as e:
            return '', f'Error executing PowerShell script: {str(e)}'

    def _execute_batch(self, file_path: str) -> Tuple[str, str]:
        """Execute batch/cmd script."""
        try:
            result = subprocess.run(
                ['cmd', '/c', file_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(file_path)
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return '', 'Execution timed out after 30 seconds'
        except Exception as e:
            return '', f'Error executing batch script: {str(e)}'

    def _execute_binary(self, file_path: str) -> Tuple[str, str]:
        """Execute binary executable."""
        try:
            # Just launch it, don't wait for output
            subprocess.Popen(
                [file_path],
                cwd=os.path.dirname(file_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return 'Executable launched successfully', ''
        except Exception as e:
            return '', f'Error executing binary: {str(e)}'

    def _execute_dll(self, file_path: str) -> Tuple[str, str]:
        """Execute DLL using rundll32."""
        try:
            # Note: This requires knowing the entry point, using a generic one
            result = subprocess.run(
                ['rundll32', file_path, 'DllMain'],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(file_path)
            )
            return result.stdout or 'DLL executed', result.stderr
        except subprocess.TimeoutExpired:
            return '', 'Execution timed out after 30 seconds'
        except Exception as e:
            return '', f'Error executing DLL: {str(e)}'

    def _execute_javascript(self, file_path: str) -> Tuple[str, str]:
        """Execute JavaScript using cscript."""
        try:
            result = subprocess.run(
                ['cscript', '//Nologo', file_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(file_path)
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return '', 'Execution timed out after 30 seconds'
        except Exception as e:
            return '', f'Error executing JavaScript: {str(e)}'

    def _execute_vbscript(self, file_path: str) -> Tuple[str, str]:
        """Execute VBScript using cscript."""
        try:
            result = subprocess.run(
                ['cscript', '//Nologo', file_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(file_path)
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return '', 'Execution timed out after 30 seconds'
        except Exception as e:
            return '', f'Error executing VBScript: {str(e)}'

    def _execute_wscript(self, file_path: str) -> Tuple[str, str]:
        """Execute Windows Script File."""
        try:
            result = subprocess.run(
                ['cscript', '//Nologo', file_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(file_path)
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return '', 'Execution timed out after 30 seconds'
        except Exception as e:
            return '', f'Error executing WSF: {str(e)}'

    def _execute_hta(self, file_path: str) -> Tuple[str, str]:
        """Execute HTML Application."""
        try:
            # Launch with mshta
            subprocess.Popen(
                ['mshta', file_path],
                cwd=os.path.dirname(file_path)
            )
            return 'HTA application launched', ''
        except Exception as e:
            return '', f'Error executing HTA: {str(e)}'

    def get_file_info(self, file_path: str) -> dict:
        """
        Get basic file information.

        Args:
            file_path: Path to the file

        Returns:
            Dictionary with file information
        """
        try:
            stat = os.stat(file_path)
            path_obj = Path(file_path)

            return {
                'name': path_obj.name,
                'extension': path_obj.suffix,
                'size': stat.st_size,
                'size_kb': stat.st_size / 1024,
                'size_mb': stat.st_size / (1024 * 1024),
                'can_execute': self.can_execute(file_path),
                'is_text': self._is_likely_text(path_obj.suffix),
                'path': str(path_obj.absolute())
            }
        except Exception as e:
            return {'error': str(e)}

    def _is_likely_text(self, extension: str) -> bool:
        """Check if file extension suggests text content."""
        text_extensions = {
            '.txt', '.log', '.py', '.ps1', '.bat', '.cmd',
            '.js', '.vbs', '.vbe', '.wsf', '.xml', '.html',
            '.htm', '.json', '.csv', '.ini', '.cfg', '.conf',
            '.c', '.cpp', '.h', '.java', '.cs', '.php', '.rb',
            '.pl', '.sh', '.bash', '.zsh', '.yaml', '.yml'
        }
        return extension.lower() in text_extensions


# Singleton instance
_viewer_executor = None


def get_viewer_executor() -> FileViewerExecutor:
    """Get or create the singleton FileViewerExecutor instance."""
    global _viewer_executor
    if _viewer_executor is None:
        _viewer_executor = FileViewerExecutor()
    return _viewer_executor
