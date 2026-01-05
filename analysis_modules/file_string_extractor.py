"""
File String Extractor for Static Analysis
Optimized for large files (30MB-100MB+) with chunked processing
"""

import re
import os
import math
from typing import Dict, List, Set, Optional, Callable
from collections import Counter
from datetime import datetime


class FileStringExtractor:
    """
    Extract strings from files with optimization for large files
    Uses chunked processing to handle files up to 100MB+ efficiently
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize the file string extractor

        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose

        # Compile regex patterns once
        self.string_patterns = {
            'ascii': re.compile(rb'[\x20-\x7E]{4,}'),
            'unicode': re.compile(rb'(?:[\x20-\x7E]\x00){4,}'),
        }

    def extract_strings_from_file(
        self,
        file_path: str,
        min_length: int = 4,
        max_strings: int = 50000,
        include_unicode: bool = True,
        enable_quality_filter: bool = True,
        progress_callback: Optional[Callable] = None,
        scan_mode: str = "quick"
    ) -> Dict[str, any]:
        """
        Extract strings from a file with optimized chunked processing

        Args:
            file_path: Path to the file to analyze
            min_length: Minimum string length (default: 4)
            max_strings: Maximum total strings to extract (default: 50000)
            include_unicode: Include Unicode (UTF-16LE) strings
            enable_quality_filter: Apply quality filtering
            progress_callback: Optional callback(bytes_processed, total_bytes, current_strings)
            scan_mode: 'quick' (stop at max_strings) or 'full' (scan entire file)

        Returns:
            Dictionary containing extracted strings and metadata
        """
        result = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': 0,
            'strings': {
                'ascii': set(),
                'unicode': set(),
                'urls': set(),
                'paths': set(),
                'ips': set(),
                'registry': set(),
                'environment': set(),
            },
            'bytes_processed': 0,
            'errors': [],
            'scan_mode': scan_mode,
            'extraction_time': None
        }

        try:
            start_time = datetime.now()

            # Get file size
            file_size = os.path.getsize(file_path)
            result['file_size'] = file_size

            if self.verbose:
                print(f"[FileExtractor] Extracting strings from {file_path} ({file_size:,} bytes)")

            # Optimize chunk size based on file size
            chunk_size = self._get_optimal_chunk_size(file_size)

            # For very large files, use memory-mapped I/O
            if file_size > 50 * 1024 * 1024:  # 50MB
                self._extract_with_mmap(
                    file_path, result, min_length, max_strings,
                    include_unicode, enable_quality_filter,
                    progress_callback, scan_mode
                )
            else:
                self._extract_with_chunks(
                    file_path, result, min_length, max_strings,
                    include_unicode, enable_quality_filter,
                    progress_callback, chunk_size, scan_mode
                )

            # Convert sets to sorted lists
            for key in result['strings']:
                result['strings'][key] = sorted(list(result['strings'][key]))[:max_strings]

            end_time = datetime.now()
            result['extraction_time'] = (end_time - start_time).total_seconds()

            total_strings = sum(len(s) for s in result['strings'].values())
            if self.verbose:
                print(f"[FileExtractor] Extracted {total_strings} strings in {result['extraction_time']:.2f}s")

        except Exception as e:
            error_msg = f"Error extracting strings from {file_path}: {str(e)}"
            result['errors'].append(error_msg)
            if self.verbose:
                print(f"[FileExtractor] {error_msg}")
                import traceback
                traceback.print_exc()

        return result

    def _get_optimal_chunk_size(self, file_size: int) -> int:
        """
        Determine optimal chunk size based on file size

        Args:
            file_size: Size of file in bytes

        Returns:
            Optimal chunk size in bytes
        """
        if file_size < 1024 * 1024:  # < 1MB
            return 256 * 1024  # 256KB chunks
        elif file_size < 10 * 1024 * 1024:  # < 10MB
            return 1024 * 1024  # 1MB chunks
        elif file_size < 50 * 1024 * 1024:  # < 50MB
            return 2 * 1024 * 1024  # 2MB chunks
        else:  # >= 50MB
            return 4 * 1024 * 1024  # 4MB chunks

    def _extract_with_chunks(
        self,
        file_path: str,
        result: Dict,
        min_length: int,
        max_strings: int,
        include_unicode: bool,
        enable_quality_filter: bool,
        progress_callback: Optional[Callable],
        chunk_size: int,
        scan_mode: str
    ):
        """Extract strings using chunked file reading"""
        file_size = result['file_size']

        with open(file_path, 'rb') as f:
            overlap_size = 1024  # Overlap to catch strings spanning chunks
            overlap_buffer = b''
            bytes_processed = 0

            while True:
                # Read chunk
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                # Combine with overlap from previous chunk
                data = overlap_buffer + chunk
                bytes_processed += len(chunk)
                result['bytes_processed'] = bytes_processed

                # Extract strings from this chunk
                self._extract_strings_from_buffer(
                    data, result['strings'], min_length,
                    include_unicode, enable_quality_filter
                )

                # Progress callback
                if progress_callback:
                    try:
                        total_strings = sum(len(s) for s in result['strings'].values())
                        progress_callback(bytes_processed, file_size, total_strings)
                    except Exception as e:
                        if self.verbose:
                            print(f"[FileExtractor] Callback error: {e}")

                # Check if we've hit max strings (quick mode)
                total_strings = sum(len(s) for s in result['strings'].values())
                if scan_mode == "quick" and total_strings >= max_strings:
                    if self.verbose:
                        print(f"[FileExtractor] Reached max strings ({max_strings}) in quick mode")
                    break

                # Save overlap for next iteration
                overlap_buffer = chunk[-overlap_size:] if len(chunk) >= overlap_size else chunk

    def _extract_with_mmap(
        self,
        file_path: str,
        result: Dict,
        min_length: int,
        max_strings: int,
        include_unicode: bool,
        enable_quality_filter: bool,
        progress_callback: Optional[Callable],
        scan_mode: str
    ):
        """Extract strings using memory-mapped I/O for large files"""
        import mmap

        file_size = result['file_size']
        chunk_size = 4 * 1024 * 1024  # 4MB chunks for mmap

        with open(file_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                offset = 0
                overlap_size = 1024

                while offset < file_size:
                    # Calculate chunk boundaries
                    chunk_start = max(0, offset - overlap_size)
                    chunk_end = min(file_size, offset + chunk_size)

                    # Read chunk from mmap
                    data = mmapped_file[chunk_start:chunk_end]

                    # Extract strings
                    self._extract_strings_from_buffer(
                        data, result['strings'], min_length,
                        include_unicode, enable_quality_filter
                    )

                    offset += chunk_size
                    result['bytes_processed'] = min(offset, file_size)

                    # Progress callback
                    if progress_callback:
                        try:
                            total_strings = sum(len(s) for s in result['strings'].values())
                            progress_callback(result['bytes_processed'], file_size, total_strings)
                        except Exception as e:
                            if self.verbose:
                                print(f"[FileExtractor] Callback error: {e}")

                    # Check if we've hit max strings (quick mode)
                    total_strings = sum(len(s) for s in result['strings'].values())
                    if scan_mode == "quick" and total_strings >= max_strings:
                        if self.verbose:
                            print(f"[FileExtractor] Reached max strings ({max_strings}) in quick mode")
                        break

    def _extract_strings_from_buffer(
        self,
        data: bytes,
        string_dict: Dict[str, Set[str]],
        min_length: int,
        include_unicode: bool,
        enable_quality_filter: bool
    ):
        """
        Extract strings from a data buffer

        Args:
            data: Bytes to extract strings from
            string_dict: Dictionary to store extracted strings
            min_length: Minimum string length
            include_unicode: Include Unicode strings
            enable_quality_filter: Apply quality filtering
        """
        if not data:
            return

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
                        string_dict['ascii'].add(string)
                        self._categorize_string(string, string_dict)
            except Exception:
                continue

        # Extract Unicode strings (UTF-16LE)
        if include_unicode:
            if min_length == 4:
                unicode_pattern = self.string_patterns['unicode']
            else:
                pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
                unicode_pattern = re.compile(pattern)

            for match in unicode_pattern.finditer(data):
                try:
                    string = match.group().decode('utf-16le', errors='ignore')
                    if len(string) >= min_length:
                        if not enable_quality_filter or self._is_quality_string(string, min_length):
                            string_dict['unicode'].add(string)
                            self._categorize_string(string, string_dict)
                except Exception:
                    continue

    def _categorize_string(self, string: str, string_dict: Dict[str, Set[str]]):
        """Categorize strings into specific types"""
        # URLs
        if re.search(r'https?://', string, re.IGNORECASE) or re.search(r'www\.', string, re.IGNORECASE):
            string_dict['urls'].add(string)
        # Environment variables
        elif '=' in string and len(string.split('=', 1)) == 2:
            key, value = string.split('=', 1)
            if (key.isupper() or key.startswith('_') or
                any(env_name in key.upper() for env_name in
                    ['PATH', 'HOME', 'USER', 'TEMP', 'COMPUTER', 'PROCESSOR'])):
                string_dict['environment'].add(string)
        # File paths
        elif '\\' in string or (string.count('/') > 1 and len(string) > 10):
            if re.match(r'^[a-zA-Z]:\\', string) or string.startswith('\\\\') or string.startswith('/'):
                string_dict['paths'].add(string)
        # IP addresses
        elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', string):
            if self._is_valid_ip(string):
                string_dict['ips'].add(string)
        # Registry keys
        elif string.startswith('HKEY_') or string.startswith('HKLM\\') or string.startswith('HKCU\\'):
            string_dict['registry'].add(string)

    def _is_valid_ip(self, string: str) -> bool:
        """Validate IP address"""
        ip_match = re.search(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', string)
        if not ip_match:
            return False
        try:
            octets = [int(x) for x in ip_match.groups()]
            return all(0 <= octet <= 255 for octet in octets)
        except ValueError:
            return False

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy"""
        if not string:
            return 0.0
        char_counts = Counter(string)
        length = len(string)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def _get_vowel_ratio(self, string: str) -> float:
        """Calculate vowel ratio"""
        if not string:
            return 0.0
        vowels = 'aeiouAEIOU'
        alpha_chars = [c for c in string if c.isalpha()]
        if not alpha_chars:
            return 0.0
        vowel_count = sum(1 for c in alpha_chars if c in vowels)
        return vowel_count / len(alpha_chars)

    def _has_excessive_repetition(self, string: str) -> bool:
        """Check for excessive repetition"""
        if len(string) < 4:
            return False
        char_counts = Counter(string)
        most_common_char, most_common_count = char_counts.most_common(1)[0]
        if most_common_count / len(string) > 0.6:
            return True
        return False

    def _is_quality_string(self, string: str, min_length: int = 4) -> bool:
        """
        Determine if string meets quality criteria

        Args:
            string: String to evaluate
            min_length: Minimum length

        Returns:
            True if passes quality checks
        """
        if len(string) < min_length:
            return False

        # Always keep URLs, IPs, registry keys
        if re.search(r'https?://', string, re.IGNORECASE):
            return True
        if string.startswith('HKEY_') or string.startswith('HKLM\\') or string.startswith('HKCU\\'):
            return True
        if re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', string) and self._is_valid_ip(string):
            return True

        # Check for excessive repetition
        if self._has_excessive_repetition(string):
            return False

        # Check entropy
        entropy = self._calculate_entropy(string)
        if entropy > 4.5:
            return False

        # Check vowel ratio for alphabetic strings
        alpha_count = sum(1 for c in string if c.isalpha())
        if alpha_count > len(string) * 0.3:
            vowel_ratio = self._get_vowel_ratio(string)
            if vowel_ratio < 0.15 and not ('\\' in string or '/' in string or '.' in string):
                return False

        return True

    def export_to_txt(
        self,
        extraction_result: Dict,
        output_path: str,
        include_metadata: bool = True
    ) -> bool:
        """
        Export extracted strings to a text file (Option B format)

        Args:
            extraction_result: Result from extract_strings_from_file()
            output_path: Path to output TXT file
            include_metadata: Include header with metadata

        Returns:
            True if successful
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                if include_metadata:
                    # Header with metadata
                    f.write("=" * 80 + "\n")
                    f.write(f"File: {extraction_result['file_name']}\n")
                    f.write(f"Path: {extraction_result['file_path']}\n")
                    f.write(f"Size: {extraction_result['file_size']:,} bytes\n")
                    f.write(f"Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Scan Mode: {extraction_result.get('scan_mode', 'N/A')}\n")

                    total_strings = sum(len(s) for s in extraction_result['strings'].values())
                    f.write(f"Total Strings: {total_strings:,}\n")

                    if extraction_result.get('extraction_time'):
                        f.write(f"Extraction Time: {extraction_result['extraction_time']:.2f}s\n")

                    f.write("=" * 80 + "\n\n")

                # Write categorized strings
                strings_data = extraction_result['strings']

                # URLs
                if strings_data.get('urls'):
                    f.write(f"URLS ({len(strings_data['urls'])}):\n")
                    f.write("-" * 80 + "\n")
                    for s in strings_data['urls']:
                        f.write(f"{s}\n")
                    f.write("\n")

                # IPs
                if strings_data.get('ips'):
                    f.write(f"IP ADDRESSES ({len(strings_data['ips'])}):\n")
                    f.write("-" * 80 + "\n")
                    for s in strings_data['ips']:
                        f.write(f"{s}\n")
                    f.write("\n")

                # Paths
                if strings_data.get('paths'):
                    f.write(f"FILE PATHS ({len(strings_data['paths'])}):\n")
                    f.write("-" * 80 + "\n")
                    for s in strings_data['paths']:
                        f.write(f"{s}\n")
                    f.write("\n")

                # Registry
                if strings_data.get('registry'):
                    f.write(f"REGISTRY KEYS ({len(strings_data['registry'])}):\n")
                    f.write("-" * 80 + "\n")
                    for s in strings_data['registry']:
                        f.write(f"{s}\n")
                    f.write("\n")

                # Environment
                if strings_data.get('environment'):
                    f.write(f"ENVIRONMENT VARIABLES ({len(strings_data['environment'])}):\n")
                    f.write("-" * 80 + "\n")
                    for s in strings_data['environment']:
                        f.write(f"{s}\n")
                    f.write("\n")

                # All ASCII strings
                if strings_data.get('ascii'):
                    f.write(f"ASCII STRINGS ({len(strings_data['ascii'])}):\n")
                    f.write("-" * 80 + "\n")
                    for s in strings_data['ascii']:
                        f.write(f"{s}\n")
                    f.write("\n")

                # All Unicode strings
                if strings_data.get('unicode'):
                    f.write(f"UNICODE STRINGS ({len(strings_data['unicode'])}):\n")
                    f.write("-" * 80 + "\n")
                    for s in strings_data['unicode']:
                        f.write(f"{s}\n")
                    f.write("\n")

            if self.verbose:
                print(f"[FileExtractor] Exported strings to {output_path}")

            return True

        except Exception as e:
            if self.verbose:
                print(f"[FileExtractor] Export error: {e}")
            return False
