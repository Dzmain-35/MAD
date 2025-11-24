"""
Enhanced Memory String Extractor for Process Monitor
Implements dynamic string extraction from process memory similar to Process Hacker
Uses Windows API to read process memory regions directly

NOTE: This module requires Windows platform. On Linux/Unix systems,
the fallback method will be used instead.
"""

import sys
import platform

# Check if running on Windows
if platform.system() != 'Windows':
    raise ImportError(f"Memory string extractor requires Windows. Current platform: {platform.system()}")

import ctypes
from ctypes import wintypes
import re
import psutil
from typing import List, Dict, Set, Optional
from collections import defaultdict

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

# Windows API Structures
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# Load Windows API functions
kernel32 = ctypes.windll.kernel32

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t
]
VirtualQueryEx.restype = ctypes.c_size_t

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
ReadProcessMemory.restype = wintypes.BOOL


class MemoryStringExtractor:
    """
    Enhanced string extractor that reads directly from process memory
    Similar to Process Hacker's memory search functionality
    """
    
    def __init__(self):
        self.string_patterns = {
            'ascii': re.compile(rb'[\x20-\x7E]{4,}'),
            'unicode': re.compile(rb'(?:[\x20-\x7E]\x00){4,}'),
        }
    
    def extract_strings_from_memory(
        self,
        pid: int,
        min_length: int = 4,
        max_strings: int = 5000,
        include_unicode: bool = True,
        filter_regions: Optional[List[str]] = None
    ) -> Dict[str, any]:
        """
        Extract strings from process memory regions
        
        Args:
            pid: Process ID
            min_length: Minimum string length
            max_strings: Maximum number of strings to extract
            include_unicode: Include Unicode strings
            filter_regions: List of region types to scan ['private', 'image', 'mapped']
                          If None, scans all readable regions
        
        Returns:
            Dictionary containing extracted strings and metadata
        """
        result = {
            'pid': pid,
            'strings': {
                'ascii': set(),
                'unicode': set(),
                'urls': set(),
                'paths': set(),
                'ips': set(),
                'registry': set(),
            },
            'memory_regions': [],
            'total_bytes_scanned': 0,
            'errors': []
        }
        
        if filter_regions is None:
            filter_regions = ['private', 'image', 'mapped']
        
        try:
            # Open process with read permissions
            h_process = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not h_process:
                result['errors'].append(f"Failed to open process {pid}")
                return result
            
            try:
                # Enumerate memory regions
                address = 0
                max_address = 0x7FFFFFFF0000  # Maximum user-mode address on x64
                
                while address < max_address:
                    mbi = MEMORY_BASIC_INFORMATION()
                    
                    # Query memory region
                    if VirtualQueryEx(
                        h_process,
                        ctypes.c_void_p(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    ) == 0:
                        break
                    
                    # Check if region is readable and matches filter
                    if self._is_readable_region(mbi) and self._should_scan_region(mbi, filter_regions):
                        region_info = {
                            'base': hex(mbi.BaseAddress),
                            'size': mbi.RegionSize,
                            'type': self._get_region_type(mbi),
                            'protection': self._get_protection_string(mbi.Protect)
                        }
                        result['memory_regions'].append(region_info)
                        
                        # Read memory from this region
                        memory_data = self._read_memory_region(h_process, mbi)
                        
                        if memory_data:
                            result['total_bytes_scanned'] += len(memory_data)
                            
                            # Extract strings from memory data
                            self._extract_strings_from_buffer(
                                memory_data,
                                result['strings'],
                                min_length,
                                include_unicode
                            )
                            
                            # Stop if we've collected enough strings
                            total_strings = sum(len(s) for s in result['strings'].values())
                            if total_strings >= max_strings:
                                break
                    
                    # Move to next region
                    address = mbi.BaseAddress + mbi.RegionSize
                    
                    # Safety check to prevent infinite loop
                    if mbi.RegionSize == 0:
                        address += 0x1000  # Move by page size
            
            finally:
                CloseHandle(h_process)
        
        except Exception as e:
            result['errors'].append(f"Error scanning process {pid}: {str(e)}")
        
        # Convert sets to sorted lists and limit
        for key in result['strings']:
            result['strings'][key] = sorted(list(result['strings'][key]))[:max_strings // 5]
        
        return result
    
    def _is_readable_region(self, mbi: MEMORY_BASIC_INFORMATION) -> bool:
        """Check if memory region is readable"""
        if mbi.State != MEM_COMMIT:
            return False
        
        if mbi.Protect & PAGE_GUARD:
            return False
        
        if mbi.Protect & PAGE_NOACCESS:
            return False
        
        readable_protections = [
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY
        ]
        
        return any(mbi.Protect & prot for prot in readable_protections)
    
    def _should_scan_region(self, mbi: MEMORY_BASIC_INFORMATION, filter_regions: List[str]) -> bool:
        """Check if region type should be scanned"""
        region_type = self._get_region_type(mbi)
        return region_type in filter_regions
    
    def _get_region_type(self, mbi: MEMORY_BASIC_INFORMATION) -> str:
        """Get human-readable region type"""
        if mbi.Type & MEM_IMAGE:
            return 'image'
        elif mbi.Type & MEM_MAPPED:
            return 'mapped'
        elif mbi.Type & MEM_PRIVATE:
            return 'private'
        return 'unknown'
    
    def _get_protection_string(self, protect: int) -> str:
        """Convert protection flags to readable string"""
        protections = []
        if protect & PAGE_READONLY:
            protections.append('R')
        if protect & PAGE_READWRITE:
            protections.append('RW')
        if protect & PAGE_WRITECOPY:
            protections.append('WC')
        if protect & PAGE_EXECUTE:
            protections.append('X')
        if protect & PAGE_EXECUTE_READ:
            protections.append('RX')
        if protect & PAGE_EXECUTE_READWRITE:
            protections.append('RWX')
        if protect & PAGE_EXECUTE_WRITECOPY:
            protections.append('WCX')
        
        return '|'.join(protections) if protections else 'NOACCESS'
    
    def _read_memory_region(
        self,
        h_process: wintypes.HANDLE,
        mbi: MEMORY_BASIC_INFORMATION,
        max_chunk_size: int = 1024 * 1024  # 1MB chunks
    ) -> Optional[bytes]:
        """
        Read memory from a specific region
        
        Args:
            h_process: Process handle
            mbi: Memory region information
            max_chunk_size: Maximum size to read at once
        
        Returns:
            Bytes read from memory or None on error
        """
        try:
            size_to_read = min(mbi.RegionSize, max_chunk_size)
            buffer = ctypes.create_string_buffer(size_to_read)
            bytes_read = ctypes.c_size_t()
            
            if ReadProcessMemory(
                h_process,
                ctypes.c_void_p(mbi.BaseAddress),
                buffer,
                size_to_read,
                ctypes.byref(bytes_read)
            ):
                return buffer.raw[:bytes_read.value]
            
        except Exception as e:
            # Silent fail - some regions may not be readable
            pass
        
        return None
    
    def _extract_strings_from_buffer(
        self,
        data: bytes,
        string_dict: Dict[str, Set[str]],
        min_length: int,
        include_unicode: bool
    ):
        """
        Extract various types of strings from memory buffer
        
        Args:
            data: Memory buffer
            string_dict: Dictionary to store extracted strings
            min_length: Minimum string length
            include_unicode: Whether to extract Unicode strings
        """
        # Extract ASCII strings
        pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        ascii_pattern = re.compile(pattern)
        
        for match in ascii_pattern.finditer(data):
            try:
                string = match.group().decode('ascii', errors='ignore')
                if len(string) >= min_length:
                    string_dict['ascii'].add(string)
                    
                    # Categorize strings
                    self._categorize_string(string, string_dict)
                    
            except:
                pass
        
        # Extract Unicode strings (UTF-16LE)
        if include_unicode:
            # Look for null-terminated wide strings
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
            unicode_re = re.compile(unicode_pattern)
            
            for match in unicode_re.finditer(data):
                try:
                    string = match.group().decode('utf-16le', errors='ignore')
                    if len(string) >= min_length:
                        string_dict['unicode'].add(string)
                        
                        # Categorize strings
                        self._categorize_string(string, string_dict)
                        
                except:
                    pass
    
    def _categorize_string(self, string: str, string_dict: Dict[str, Set[str]]):
        """Categorize strings into specific types (URLs, paths, IPs, etc.)"""
        # URLs
        if re.search(r'https?://', string, re.IGNORECASE) or re.search(r'www\.', string, re.IGNORECASE):
            string_dict['urls'].add(string)
        
        # File paths
        elif '\\' in string or (string.count('/') > 1 and len(string) > 10):
            # Windows paths or Unix paths
            if re.match(r'^[a-zA-Z]:\\', string) or string.startswith('\\\\') or string.startswith('/'):
                string_dict['paths'].add(string)
        
        # IP addresses
        elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', string):
            string_dict['ips'].add(string)
        
        # Registry keys
        elif string.startswith('HKEY_') or string.startswith('HKLM\\') or string.startswith('HKCU\\'):
            string_dict['registry'].add(string)
    
    def format_results(self, results: Dict) -> str:
        """Format extraction results for display"""
        output = []
        output.append(f"String Extraction Results for PID {results['pid']}")
        output.append("=" * 80)
        output.append(f"Total bytes scanned: {results['total_bytes_scanned']:,}")
        output.append(f"Memory regions scanned: {len(results['memory_regions'])}")
        output.append("")
        
        # Show string counts
        output.append("String Counts by Type:")
        for str_type, strings in results['strings'].items():
            output.append(f"  {str_type.capitalize()}: {len(strings)}")
        output.append("")
        
        # Show categorized strings
        for str_type, strings in results['strings'].items():
            if strings and str_type != 'ascii':  # Skip ascii as it's too general
                output.append(f"\n{str_type.upper()} ({len(strings)}):")
                output.append("-" * 80)
                for s in list(strings)[:20]:  # Show first 20
                    output.append(f"  {s}")
                if len(strings) > 20:
                    output.append(f"  ... and {len(strings) - 20} more")
        
        # Show errors if any
        if results['errors']:
            output.append("\nErrors:")
            for error in results['errors']:
                output.append(f"  {error}")
        
        return "\n".join(output)
    
    def get_interesting_strings(self, results: Dict) -> Dict[str, List[str]]:
        """
        Get the most interesting strings from extraction results
        
        Returns:
            Dictionary with categorized interesting strings
        """
        interesting = {
            'commands': [],
            'network': [],
            'files': [],
            'crypto': [],
            'suspicious': []
        }
        
        all_strings = (
            list(results['strings']['ascii']) +
            list(results['strings']['unicode'])
        )
        
        # Command line indicators
        cmd_keywords = ['cmd', 'powershell', 'wscript', 'cscript', 'bash', 'sh']
        for s in all_strings:
            if any(kw in s.lower() for kw in cmd_keywords):
                interesting['commands'].append(s)
        
        # Network indicators (IPs, URLs already categorized)
        interesting['network'] = (
            list(results['strings']['urls']) +
            list(results['strings']['ips'])
        )
        
        # File paths
        interesting['files'] = list(results['strings']['paths'])
        
        # Crypto/encoding indicators
        crypto_keywords = ['base64', 'encrypt', 'decrypt', 'cipher', 'aes', 'rsa']
        for s in all_strings:
            if any(kw in s.lower() for kw in crypto_keywords):
                interesting['crypto'].append(s)
        
        # Suspicious strings
        suspicious_keywords = [
            'keylog', 'inject', 'hook', 'dump', 'credential',
            'password', 'token', 'payload', 'shellcode'
        ]
        for s in all_strings:
            if any(kw in s.lower() for kw in suspicious_keywords):
                interesting['suspicious'].append(s)
        
        # Limit results
        for key in interesting:
            interesting[key] = interesting[key][:50]
        
        return interesting


# Testing function
def test_memory_extraction():
    """Test the memory string extractor"""
    extractor = MemoryStringExtractor()
    
    # Get a test process (e.g., current process or notepad)
    current_pid = psutil.Process().pid
    
    print(f"Testing memory extraction on PID {current_pid}")
    print("=" * 80)
    
    # Extract strings
    results = extractor.extract_strings_from_memory(
        pid=current_pid,
        min_length=4,
        max_strings=1000,
        include_unicode=True,
        filter_regions=['private', 'image']
    )
    
    # Display results
    print(extractor.format_results(results))
    print("\n" + "=" * 80)
    
    # Show interesting strings
    interesting = extractor.get_interesting_strings(results)
    print("\nInteresting Strings Found:")
    for category, strings in interesting.items():
        if strings:
            print(f"\n{category.upper()}:")
            for s in strings[:10]:
                print(f"  {s}")


if __name__ == "__main__":
    test_memory_extraction()