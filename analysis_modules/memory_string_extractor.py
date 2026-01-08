"""
Enhanced Memory String Extractor for Process Monitor
Implements dynamic string extraction from process memory similar to Process Hacker
Uses Windows API to read process memory regions directly

NOTE: This module requires Windows platform. On Linux/Unix systems,
the fallback method will be used instead.
"""

import sys
import platform
import re
import psutil
import math
import time
from typing import List, Dict, Set, Optional
from collections import defaultdict, Counter

# Check if running on Windows and import Windows-specific modules
IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes
else:
    # Define dummy types for non-Windows platforms
    ctypes = None
    wintypes = None

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # Works on protected processes
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

# Windows API Structures (only on Windows)
if IS_WINDOWS:
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
else:
    # Dummy definitions for non-Windows
    MEMORY_BASIC_INFORMATION = None
    OpenProcess = None
    CloseHandle = None
    VirtualQueryEx = None
    ReadProcessMemory = None


class MemoryStringExtractor:
    """
    Enhanced string extractor that reads directly from process memory
    Similar to Process Hacker's memory search functionality
    """

    def __init__(self, verbose: bool = False, cache_ttl: int = 30):
        """
        Initialize the memory string extractor

        Args:
            verbose: Enable verbose logging
            cache_ttl: Cache time-to-live in seconds (default: 30)
        """
        if not IS_WINDOWS:
            raise RuntimeError("MemoryStringExtractor requires Windows platform")

        self.verbose = verbose
        self.cache_ttl = cache_ttl
        self.cache = {}  # PID -> (timestamp, results)

        self.string_patterns = {
            'ascii': re.compile(rb'[\x20-\x7E]{4,}'),
            'unicode': re.compile(rb'(?:[\x20-\x7E]\x00){4,}'),
        }

        if self.verbose:
            print(f"[MemoryExtractor] Initialized on {platform.system()}")
    
    def extract_strings_from_memory(
        self,
        pid: int,
        min_length: int = 10,
        max_strings: int = 20000,
        include_unicode: bool = True,
        filter_regions: Optional[List[str]] = None,
        enable_quality_filter: bool = True,
        use_cache: bool = True,
        scan_mode: str = "quick",
        progress_callback: Optional[callable] = None
    ) -> Dict[str, any]:
        """
        Extract strings from process memory regions

        Args:
            pid: Process ID
            min_length: Minimum string length
            max_strings: Maximum number of strings to extract
            include_unicode: Include Unicode strings
            filter_regions: List of region types to scan ['private', 'image', 'mapped']
                          If None, defaults based on scan_mode
            enable_quality_filter: Enable quality filtering to remove low-quality strings
                                 (entropy, vowel ratio, repetition, truncation checks)
            use_cache: Use cached results if available and within TTL
            scan_mode: 'quick' (IMAGE regions only, ~1-3 sec) or 'deep' (all regions, slower)
            progress_callback: Optional callback(current_strings, total_regions, regions_scanned)
                             for progressive updates

        Returns:
            Dictionary containing extracted strings and metadata
        """
        # Set default filter_regions based on scan_mode
        if filter_regions is None:
            if scan_mode == "quick":
                filter_regions = ['image']  # Quick scan: only executable regions
            else:  # deep scan
                filter_regions = ['private', 'image', 'mapped']  # Deep scan: all regions

        # Create cache key based on parameters
        cache_key = (pid, min_length, max_strings, include_unicode,
                     tuple(filter_regions) if filter_regions else None,
                     enable_quality_filter, scan_mode)

        # Check cache if enabled
        if use_cache and cache_key in self.cache:
            timestamp, cached_result = self.cache[cache_key]
            age = time.time() - timestamp

            if age < self.cache_ttl:
                if self.verbose:
                    print(f"[MemoryExtractor] Using cached results for PID {pid} (age: {age:.1f}s, mode: {scan_mode})")
                # Return a copy to prevent modifications
                return {
                    'pid': cached_result['pid'],
                    'strings': {k: list(v) if isinstance(v, list) else v for k, v in cached_result['strings'].items()},
                    'memory_regions': cached_result['memory_regions'][:],
                    'total_bytes_scanned': cached_result['total_bytes_scanned'],
                    'errors': cached_result['errors'][:],
                    'cached': True,
                    'cache_age': age,
                    'scan_mode': scan_mode
                }

        result = {
            'pid': pid,
            'strings': {
                'ascii': set(),
                'unicode': set(),
                'urls': set(),
                'paths': set(),
                'ips': set(),
                'registry': set(),
                'environment': set(),
            },
            'strings_by_region': [],  # NEW: List of {region_info, strings} for Process Hacker style output
            'memory_regions': [],
            'total_bytes_scanned': 0,
            'errors': [],
            'cached': False,
            'scan_mode': scan_mode
        }
        
        try:
            # Multi-tiered process access strategy
            # Try from most permissive to least permissive
            h_process = None
            access_level = "none"

            # Tier 1: Try full memory read access (best case)
            h_process = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )

            if h_process:
                access_level = "full"
                if self.verbose:
                    print(f"[MemoryExtractor] Successfully opened process {pid} with FULL access")
            else:
                # Tier 2: Try limited query without memory read (for protected processes)
                if self.verbose:
                    print(f"[MemoryExtractor] Full access denied for PID {pid}, trying limited access...")

                h_process = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    pid
                )

                if h_process:
                    access_level = "limited"
                    if self.verbose:
                        print(f"[MemoryExtractor] Opened process {pid} with LIMITED access (cannot read memory)")
                    # For limited access, we can't read memory regions
                    # Return minimal result with error
                    CloseHandle(h_process)
                    error_msg = f"Process {pid} opened with limited access only - memory reading not available (protected process)"
                    result['errors'].append(error_msg)
                    result['access_level'] = access_level
                    if self.verbose:
                        print(f"[MemoryExtractor] {error_msg}")
                    return result

            if not h_process:
                error_msg = f"Failed to open process {pid} - Access Denied (likely protected system process)"
                result['errors'].append(error_msg)
                result['access_level'] = access_level
                if self.verbose:
                    print(f"[MemoryExtractor] {error_msg}")
                return result

            result['access_level'] = access_level
            
            try:
                # Enumerate memory regions
                address = 0
                max_address = 0x7FFFFFFF0000  # Maximum user-mode address on x64
                regions_scanned = 0
                regions_read = 0

                if self.verbose:
                    print(f"[MemoryExtractor] Starting memory scan for PID {pid} ({scan_mode} mode)...")

                # Track progress for callback
                callback_interval = 5  # Call callback every N regions

                while address < max_address:
                    mbi = MEMORY_BASIC_INFORMATION()

                    # Query memory region
                    if VirtualQueryEx(
                        h_process,
                        ctypes.c_void_p(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    ) == 0:
                        if self.verbose:
                            print(f"[MemoryExtractor] VirtualQueryEx returned 0, stopping enumeration")
                        break

                    # Check if region is readable and matches filter
                    if self._is_readable_region(mbi) and self._should_scan_region(mbi, filter_regions):
                        regions_scanned += 1
                        # Handle None for BaseAddress (represents address 0 in ctypes)
                        base_addr = mbi.BaseAddress if mbi.BaseAddress is not None else 0
                        region_info = {
                            'base': hex(base_addr),
                            'size': mbi.RegionSize,
                            'type': self._get_region_type(mbi),
                            'protection': self._get_protection_string(mbi.Protect)
                        }
                        result['memory_regions'].append(region_info)

                        # Read memory from this region
                        memory_data = self._read_memory_region(h_process, mbi)

                        if memory_data:
                            regions_read += 1
                            result['total_bytes_scanned'] += len(memory_data)

                            # Extract strings from memory data (for backward compatibility)
                            self._extract_strings_from_buffer(
                                memory_data,
                                result['strings'],
                                min_length,
                                include_unicode,
                                enable_quality_filter
                            )

                            # NEW: Extract strings for this specific region (Process Hacker style)
                            region_strings = self._extract_strings_from_buffer_simple(
                                memory_data,
                                min_length,
                                include_unicode,
                                enable_quality_filter
                            )

                            # Store strings with their region info
                            if region_strings:
                                result['strings_by_region'].append({
                                    'region': region_info.copy(),
                                    'strings': region_strings,
                                    'string_count': len(region_strings)
                                })

                            # Progressive callback for UI updates
                            total_strings = sum(len(s) for s in result['strings'].values())
                            if progress_callback and regions_read % callback_interval == 0:
                                try:
                                    # Convert sets to lists for callback
                                    current_strings = {k: sorted(list(v))[:max_strings]
                                                     for k, v in result['strings'].items()}
                                    progress_callback(current_strings, regions_scanned, regions_read)
                                except Exception as e:
                                    if self.verbose:
                                        print(f"[MemoryExtractor] Callback error: {e}")

                            # Stop if we've collected enough strings
                            if total_strings >= max_strings:
                                if self.verbose:
                                    print(f"[MemoryExtractor] Reached max strings limit ({max_strings})")
                                break
                        else:
                            if self.verbose and regions_scanned <= 5:  # Only log first few failures
                                base_addr = mbi.BaseAddress if mbi.BaseAddress is not None else 0
                                print(f"[MemoryExtractor] Failed to read memory at {hex(base_addr)}")

                    # Move to next region
                    # Handle None for BaseAddress (represents address 0 in ctypes)
                    base_addr = mbi.BaseAddress if mbi.BaseAddress is not None else 0
                    address = base_addr + mbi.RegionSize

                    # Safety check to prevent infinite loop
                    if mbi.RegionSize == 0:
                        address += 0x1000  # Move by page size

                if self.verbose:
                    print(f"[MemoryExtractor] Scanned {regions_scanned} regions, successfully read {regions_read} regions")
                    print(f"[MemoryExtractor] Total bytes scanned: {result['total_bytes_scanned']:,}")
                    total_strings = sum(len(s) for s in result['strings'].values())
                    print(f"[MemoryExtractor] Total strings extracted: {total_strings}")

                # Final callback with complete results
                if progress_callback:
                    try:
                        current_strings = {k: sorted(list(v))[:max_strings]
                                         for k, v in result['strings'].items()}
                        progress_callback(current_strings, regions_scanned, regions_read, final=True)
                    except Exception as e:
                        if self.verbose:
                            print(f"[MemoryExtractor] Final callback error: {e}")

            finally:
                CloseHandle(h_process)
        
        except Exception as e:
            error_msg = f"Error scanning process {pid}: {str(e)}"
            result['errors'].append(error_msg)
            if self.verbose:
                print(f"[MemoryExtractor] {error_msg}")
                import traceback
                traceback.print_exc()

        # Convert sets to sorted lists and limit
        # Use more generous per-category limits to match Process Hacker behavior
        for key in result['strings']:
            result['strings'][key] = sorted(list(result['strings'][key]))[:max_strings]

        # Validate results
        total_extracted = sum(len(s) for s in result['strings'].values())
        if total_extracted == 0:
            warning_msg = f"WARNING: No strings extracted from PID {pid}"
            if result['total_bytes_scanned'] == 0:
                warning_msg += " (no memory was scanned - possible permission issue)"
            elif len(result['memory_regions']) == 0:
                warning_msg += " (no readable memory regions found)"
            else:
                warning_msg += f" (scanned {result['total_bytes_scanned']:,} bytes from {len(result['memory_regions'])} regions)"

            result['errors'].append(warning_msg)
            if self.verbose or True:  # Always show this warning
                print(f"[MemoryExtractor] {warning_msg}")

        # Store in cache if successful extraction
        if use_cache and total_extracted > 0:
            self.cache[cache_key] = (time.time(), result)
            if self.verbose:
                print(f"[MemoryExtractor] Cached results for PID {pid} ({total_extracted} strings)")

            # Clean old cache entries (older than 2x TTL)
            current_time = time.time()
            expired_keys = [k for k, (ts, _) in self.cache.items()
                          if current_time - ts > self.cache_ttl * 2]
            for k in expired_keys:
                del self.cache[k]

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
        h_process,
        mbi,
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

            # Skip empty regions
            if size_to_read == 0:
                return None

            buffer = ctypes.create_string_buffer(size_to_read)
            bytes_read = ctypes.c_size_t()

            success = ReadProcessMemory(
                h_process,
                ctypes.c_void_p(mbi.BaseAddress),
                buffer,
                size_to_read,
                ctypes.byref(bytes_read)
            )

            if success and bytes_read.value > 0:
                return buffer.raw[:bytes_read.value]
            elif self.verbose:
                # Log first few failures for debugging
                import random
                if random.random() < 0.01:  # Log 1% of failures to avoid spam
                    base_addr = mbi.BaseAddress if mbi.BaseAddress is not None else 0
                    print(f"[MemoryExtractor] ReadProcessMemory failed at {hex(base_addr)}, bytes_read: {bytes_read.value}")

        except Exception as e:
            if self.verbose:
                import random
                if random.random() < 0.01:  # Log 1% of exceptions
                    base_addr = mbi.BaseAddress if mbi.BaseAddress is not None else 0
                    print(f"[MemoryExtractor] Exception reading memory at {hex(base_addr)}: {e}")

        return None
    
    def _extract_strings_from_buffer(
        self,
        data: bytes,
        string_dict: Dict[str, Set[str]],
        min_length: int,
        include_unicode: bool,
        enable_quality_filter: bool = True
    ):
        """
        Extract various types of strings from memory buffer

        Args:
            data: Memory buffer
            string_dict: Dictionary to store extracted strings
            min_length: Minimum string length
            include_unicode: Whether to extract Unicode strings
            enable_quality_filter: Whether to apply quality filtering
        """
        if not data:
            return

        strings_before = sum(len(s) for s in string_dict.values())

        # Extract ASCII strings
        # Use custom pattern for different min_length, or pre-compiled for length 4
        if min_length == 4:
            ascii_pattern = self.string_patterns['ascii']
        else:
            pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            ascii_pattern = re.compile(pattern)

        for match in ascii_pattern.finditer(data):
            try:
                string = match.group().decode('ascii', errors='ignore')
                # Apply quality filter if enabled
                if len(string) >= min_length:
                    if not enable_quality_filter or self._is_quality_string(string, min_length):
                        string_dict['ascii'].add(string)

                        # Categorize strings
                        self._categorize_string(string, string_dict)

            except Exception:
                continue

        # Extract Unicode strings (UTF-16LE)
        if include_unicode:
            # Use custom pattern for different min_length, or pre-compiled for length 4
            if min_length == 4:
                unicode_pattern = self.string_patterns['unicode']
            else:
                unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
                unicode_pattern = re.compile(unicode_pattern)

            for match in unicode_pattern.finditer(data):
                try:
                    string = match.group().decode('utf-16le', errors='ignore')
                    # Apply quality filter if enabled
                    if len(string) >= min_length:
                        if not enable_quality_filter or self._is_quality_string(string, min_length):
                            string_dict['unicode'].add(string)

                            # Categorize strings
                            self._categorize_string(string, string_dict)

                except Exception:
                    continue

        # Log if verbose and we found strings
        if self.verbose:
            strings_after = sum(len(s) for s in string_dict.values())
            strings_found = strings_after - strings_before
            if strings_found > 0 and strings_before < 100:  # Log first few buffers with strings
                print(f"[MemoryExtractor] Found {strings_found} strings in {len(data):,} byte buffer")
    
    def _categorize_string(self, string: str, string_dict: Dict[str, Set[str]]):
        """Categorize strings into specific types (URLs, paths, IPs, etc.)"""
        # URLs
        if re.search(r'https?://', string, re.IGNORECASE) or re.search(r'www\.', string, re.IGNORECASE):
            string_dict['urls'].add(string)

        # Environment variables (detect KEY=VALUE format with common env var names)
        elif '=' in string and len(string.split('=', 1)) == 2:
            key, value = string.split('=', 1)
            # Common environment variable patterns
            if (key.isupper() or key.startswith('_') or
                any(env_name in key.upper() for env_name in
                    ['PATH', 'HOME', 'USER', 'TEMP', 'COMPUTER', 'PROCESSOR',
                     'SYSTEM', 'PROGRAM', 'APP', 'LOCAL', 'ROAMING', 'PUBLIC',
                     'DRIVE', 'DIR', 'NAME', 'NUMBER', 'LOGON'])):
                string_dict['environment'].add(string)

        # File paths
        elif '\\' in string or (string.count('/') > 1 and len(string) > 10):
            # Windows paths or Unix paths
            if re.match(r'^[a-zA-Z]:\\', string) or string.startswith('\\\\') or string.startswith('/'):
                string_dict['paths'].add(string)

        # IP addresses (with proper validation)
        elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', string):
            if self._is_valid_ip(string):
                string_dict['ips'].add(string)

        # Registry keys
        elif string.startswith('HKEY_') or string.startswith('HKLM\\') or string.startswith('HKCU\\'):
            string_dict['registry'].add(string)

    def _extract_strings_from_buffer_simple(
        self,
        data: bytes,
        min_length: int,
        include_unicode: bool,
        enable_quality_filter: bool = True
    ) -> List[str]:
        """
        Extract strings from buffer without categorization (Process Hacker style)
        Returns a simple list of all strings found in this memory buffer

        Args:
            data: Memory buffer
            min_length: Minimum string length
            include_unicode: Whether to extract Unicode strings
            enable_quality_filter: Whether to apply quality filtering

        Returns:
            List of strings found in this buffer
        """
        if not data:
            return []

        strings = []

        # Extract ASCII strings
        if min_length == 4:
            ascii_pattern = self.string_patterns['ascii']
        else:
            pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            ascii_pattern = re.compile(pattern)

        for match in ascii_pattern.finditer(data):
            try:
                string = match.group().decode('ascii', errors='ignore')
                if len(string) >= min_length:
                    if not enable_quality_filter or self._is_quality_string(string, min_length):
                        strings.append(string)
            except Exception:
                continue

        # Extract Unicode strings (UTF-16LE)
        if include_unicode:
            if min_length == 4:
                unicode_pattern = self.string_patterns['unicode']
            else:
                unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
                unicode_pattern = re.compile(unicode_pattern)

            for match in unicode_pattern.finditer(data):
                try:
                    string = match.group().decode('utf-16le', errors='ignore')
                    if len(string) >= min_length:
                        if not enable_quality_filter or self._is_quality_string(string, min_length):
                            strings.append(string)
                except Exception:
                    continue

        return strings

    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        Higher entropy = more random/encrypted
        Lower entropy = more structured/meaningful

        Returns:
            Entropy value (0.0 to ~8.0 for typical strings)
        """
        if not string:
            return 0.0

        # Count character frequencies
        char_counts = Counter(string)
        length = len(string)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _get_vowel_ratio(self, string: str) -> float:
        """
        Calculate ratio of vowels to total alphabetic characters
        Real words typically have 30-50% vowels

        Returns:
            Ratio of vowels (0.0 to 1.0)
        """
        if not string:
            return 0.0

        vowels = 'aeiouAEIOU'
        alpha_chars = [c for c in string if c.isalpha()]

        if not alpha_chars:
            return 0.0

        vowel_count = sum(1 for c in alpha_chars if c in vowels)
        return vowel_count / len(alpha_chars)

    def _has_excessive_repetition(self, string: str) -> bool:
        """
        Check if string has excessive character repetition

        Returns:
            True if string is too repetitive
        """
        if len(string) < 4:
            return False

        # Check for same character repeated
        char_counts = Counter(string)
        most_common_char, most_common_count = char_counts.most_common(1)[0]

        # If one character makes up >60% of string, it's too repetitive
        if most_common_count / len(string) > 0.6:
            return True

        # Check for repeating patterns (e.g., "ABABAB")
        for pattern_len in [2, 3]:
            if len(string) >= pattern_len * 3:
                pattern = string[:pattern_len]
                repetitions = string.count(pattern)
                if repetitions >= len(string) // pattern_len * 0.5:
                    return True

        return False

    def _is_likely_truncated(self, string: str) -> bool:
        """
        Detect if string appears to be truncated or partial

        Returns:
            True if string looks truncated
        """
        # Check for common truncation patterns
        truncation_indicators = [
            # Incomplete Windows paths
            lambda s: re.match(r'^[A-Z]:\\[^\\]*$', s) and len(s) < 15,
            # Incomplete words (ends mid-word in a path)
            lambda s: '\\' in s and s.split('\\')[-1] and not s.split('\\')[-1].strip().endswith(('.dll', '.exe', '.txt', '.log')),
            # Registry path fragments
            lambda s: s.startswith('\\REGIS') and not s.startswith('\\REGISTRY\\'),
            # Incomplete common strings
            lambda s: any(s.startswith(prefix) and len(s) < len(full) for prefix, full in [
                ('C:\\Win', 'C:\\Windows'),
                ('C:\\Prog', 'C:\\Program Files'),
                ('\\Regist', '\\Registry'),
            ]),
        ]

        return any(check(string) for check in truncation_indicators)

    def _is_valid_ip(self, string: str) -> bool:
        """
        Validate that IP address has valid octets (0-255)

        Returns:
            True if valid IP address
        """
        ip_match = re.search(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', string)
        if not ip_match:
            return False

        try:
            octets = [int(x) for x in ip_match.groups()]
            # Check each octet is in valid range
            return all(0 <= octet <= 255 for octet in octets)
        except ValueError:
            return False

    def _is_quality_string(self, string: str, min_length: int = 10) -> bool:
        """
        Determine if string meets quality criteria

        Args:
            string: String to evaluate
            min_length: Minimum acceptable length

        Returns:
            True if string passes quality checks
        """
        # Basic length check
        if len(string) < min_length:
            return False

        # Allow certain types without further filtering
        # URLs, IPs, registry keys are always kept if properly formatted
        if re.search(r'https?://', string, re.IGNORECASE):
            return True
        if string.startswith('HKEY_') or string.startswith('HKLM\\') or string.startswith('HKCU\\'):
            return True
        if re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', string) and self._is_valid_ip(string):
            return True

        # Check for excessive repetition
        if self._has_excessive_repetition(string):
            return False

        # Check if likely truncated
        if self._is_likely_truncated(string):
            return False

        # Calculate entropy - reject very high entropy (encrypted/random data)
        entropy = self._calculate_entropy(string)
        if entropy > 4.5:  # Threshold for "too random"
            return False

        # For strings with letters, check vowel ratio
        alpha_count = sum(1 for c in string if c.isalpha())
        if alpha_count > len(string) * 0.3:  # If >30% alphabetic
            vowel_ratio = self._get_vowel_ratio(string)
            # Reject strings with very few or no vowels (unless they're paths/technical)
            if vowel_ratio < 0.15 and not ('\\' in string or '/' in string or '.' in string):
                return False

        # Reject strings that are mostly special characters
        special_count = sum(1 for c in string if not c.isalnum() and c not in ' \\/:.-_')
        if special_count > len(string) * 0.4:
            return False

        return True
    
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

    def export_to_txt(
        self,
        extraction_result: Dict,
        output_path: str,
        process_name: str = "",
        include_metadata: bool = True
    ) -> bool:
        """
        Export extracted strings to a text file (Option B format)

        Args:
            extraction_result: Result from extract_strings_from_memory()
            output_path: Path to output TXT file
            process_name: Name of the process (optional)
            include_metadata: Include header with metadata

        Returns:
            True if successful
        """
        try:
            from datetime import datetime

            with open(output_path, 'w', encoding='utf-8') as f:
                if include_metadata:
                    # Header with metadata
                    f.write("=" * 80 + "\n")
                    if process_name:
                        f.write(f"Process: {process_name} (PID {extraction_result['pid']})\n")
                    else:
                        f.write(f"Process PID: {extraction_result['pid']}\n")

                    f.write(f"Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Scan Mode: {extraction_result.get('scan_mode', 'N/A')}\n")

                    total_strings = sum(len(s) for s in extraction_result['strings'].values())
                    f.write(f"Total Strings: {total_strings:,}\n")

                    f.write(f"Memory Regions Scanned: {len(extraction_result.get('memory_regions', []))}\n")
                    f.write(f"Total Bytes Scanned: {extraction_result.get('total_bytes_scanned', 0):,}\n")

                    if extraction_result.get('cached'):
                        f.write(f"Cached: Yes (age: {extraction_result.get('cache_age', 0):.1f}s)\n")

                    f.write("=" * 80 + "\n\n")

                # Write strings grouped by memory region (Process Hacker style)
                strings_by_region = extraction_result.get('strings_by_region', [])

                if strings_by_region:
                    f.write("STRINGS BY MEMORY REGION (Process Hacker Style)\n")
                    f.write("=" * 80 + "\n\n")

                    for region_data in strings_by_region:
                        region = region_data['region']
                        strings = region_data['strings']

                        # Format region header
                        base_addr = region['base']
                        size_bytes = region['size']
                        region_type = region['type'].upper()
                        protection = region['protection']

                        # Calculate end address
                        if base_addr.startswith('0x'):
                            end_addr = hex(int(base_addr, 16) + size_bytes)
                        else:
                            end_addr = hex(int(base_addr) + size_bytes)

                        f.write(f"Memory Region: {base_addr} - {end_addr} ({size_bytes:,} bytes)\n")
                        f.write(f"Type: {region_type}  |  Protection: {protection}\n")
                        f.write(f"Strings Found: {len(strings)}\n")
                        f.write("-" * 80 + "\n")

                        # Write strings from this region
                        for string in strings[:500]:  # Limit to 500 strings per region
                            f.write(f"{string}\n")

                        if len(strings) > 500:
                            f.write(f"... and {len(strings) - 500} more strings\n")

                        f.write("\n")

                else:
                    # Fallback: Use old categorized format if strings_by_region is not available
                    f.write("STRINGS (Legacy Format)\n")
                    f.write("=" * 80 + "\n\n")
                    f.write("Note: strings_by_region data not available, using legacy categorized format\n\n")

                    strings_data = extraction_result['strings']

                    # All ASCII strings
                    if strings_data.get('ascii') and len(strings_data['ascii']) > 0:
                        f.write(f"ASCII STRINGS ({len(strings_data['ascii'])}):\n")
                        f.write("-" * 80 + "\n")
                        for s in list(strings_data['ascii'])[:1000]:
                            f.write(f"{s}\n")
                        if len(strings_data['ascii']) > 1000:
                            f.write(f"... and {len(strings_data['ascii']) - 1000} more\n")
                        f.write("\n")

                    # All Unicode strings
                    if strings_data.get('unicode') and len(strings_data['unicode']) > 0:
                        f.write(f"UNICODE STRINGS ({len(strings_data['unicode'])}):\n")
                        f.write("-" * 80 + "\n")
                        for s in list(strings_data['unicode'])[:1000]:
                            f.write(f"{s}\n")
                        if len(strings_data['unicode']) > 1000:
                            f.write(f"... and {len(strings_data['unicode']) - 1000} more\n")
                        f.write("\n")

                # Errors if any
                if extraction_result.get('errors'):
                    f.write(f"ERRORS/WARNINGS:\n")
                    f.write("-" * 80 + "\n")
                    for error in extraction_result['errors']:
                        f.write(f"{error}\n")
                    f.write("\n")

            if self.verbose:
                print(f"[MemoryExtractor] Exported strings to {output_path}")

            return True

        except Exception as e:
            if self.verbose:
                print(f"[MemoryExtractor] Export error: {e}")
                import traceback
                traceback.print_exc()
            return False


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
        min_length=10,
        max_strings=20000,
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