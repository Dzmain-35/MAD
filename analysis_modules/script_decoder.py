"""
Script Decoder Module for MAD (Malware Analysis Dashboard)
Handles deobfuscation and decoding of malicious scripts, starting with JavaScript.

Author: MAD Development Team
"""

import re
import base64
import binascii
import html
import urllib.parse
from typing import Dict, List, Tuple, Optional
import logging

# Configure logging
logger = logging.getLogger(__name__)


class ScriptDecoder:
    """Main class for script deobfuscation and decoding."""

    def __init__(self):
        """Initialize the script decoder."""
        self.decode_iterations = 3  # Max iterations for recursive decoding (reduced for speed)
        self.max_content_size = 5 * 1024 * 1024  # 5MB limit for fast processing
        self.results = {
            'decoded_content': '',
            'techniques_detected': [],
            'iocs_found': [],
            'decode_layers': [],
            'suspicious_patterns': []
        }

    def analyze_script(self, content: str, file_type: str = 'javascript') -> Dict:
        """
        Main entry point for script analysis.

        Args:
            content: The script content to analyze
            file_type: Type of script (javascript, powershell, vbscript, etc.)

        Returns:
            Dictionary containing decoded content and analysis results
        """
        logger.info(f"Analyzing {file_type} script, length: {len(content)}")

        if file_type.lower() in ['javascript', 'js', 'jscript']:
            return self._analyze_javascript(content)
        else:
            # Future support for other script types
            return {'error': f'Unsupported script type: {file_type}'}

    def _analyze_javascript(self, content: str) -> Dict:
        """
        Analyze and deobfuscate JavaScript code.

        Args:
            content: JavaScript code to analyze

        Returns:
            Dictionary with decoded content and metadata
        """
        self.results = {
            'original_content': content,
            'decoded_content': content,
            'techniques_detected': [],
            'iocs_found': [],
            'decode_layers': [],
            'suspicious_patterns': []
        }

        current_content = content

        # Detect obfuscation techniques
        self._detect_js_obfuscation(current_content)

        # Iteratively decode
        for iteration in range(self.decode_iterations):
            previous_content = current_content

            # Apply decoders
            current_content = self._decode_string_fromcharcode(current_content)
            current_content = self._decode_base64_in_js(current_content)
            current_content = self._decode_hex_strings(current_content)
            current_content = self._decode_unicode_escapes(current_content)
            current_content = self._decode_url_encoding(current_content)
            current_content = self._simplify_string_concat(current_content)
            current_content = self._decode_escape_unescape(current_content)

            # Check if anything changed
            if current_content == previous_content:
                logger.info(f"Decoding stabilized at iteration {iteration + 1}")
                break

            self.results['decode_layers'].append({
                'iteration': iteration + 1,
                'length': len(current_content),
                'sample': current_content[:200] + ('...' if len(current_content) > 200 else '')
            })

        self.results['decoded_content'] = current_content

        # Extract IOCs from decoded content
        self._extract_iocs(current_content)

        # Detect suspicious patterns
        self._detect_suspicious_patterns(current_content)

        return self.results

    def _detect_js_obfuscation(self, content: str):
        """Detect JavaScript obfuscation techniques used."""
        techniques = []

        # Sample first 100KB for detection (performance optimization)
        sample = content[:100000] if len(content) > 100000 else content

        if re.search(r'String\.fromCharCode\s*\(', sample, re.IGNORECASE):
            count = len(re.findall(r'String\.fromCharCode\s*\(', sample, re.IGNORECASE))
            techniques.append(f'String.fromCharCode() encoding ({count} calls)')

        if re.search(r'eval\s*\(', sample, re.IGNORECASE):
            count = len(re.findall(r'eval\s*\(', sample, re.IGNORECASE))
            techniques.append(f'eval() usage ({count} calls)')

        if re.search(r'unescape\s*\(', sample, re.IGNORECASE):
            count = len(re.findall(r'unescape\s*\(', sample, re.IGNORECASE))
            techniques.append(f'unescape() encoding ({count} calls)')

        if re.search(r'atob\s*\(', sample, re.IGNORECASE):
            count = len(re.findall(r'atob\s*\(', sample, re.IGNORECASE))
            techniques.append(f'Base64 decoding - atob() ({count} calls)')

        if re.search(r'\\x[0-9a-fA-F]{2}', sample):
            count = len(re.findall(r'\\x[0-9a-fA-F]{2}', sample))
            if count > 10:
                techniques.append(f'Hex escape sequences ({count} instances)')

        if re.search(r'\\u[0-9a-fA-F]{4}', sample):
            count = len(re.findall(r'\\u[0-9a-fA-F]{4}', sample))
            if count > 10:
                techniques.append(f'Unicode escape sequences ({count} instances)')

        # Detect heavy string concatenation (possible obfuscation)
        concat_count = len(re.findall(r'["\'][^"\']{1,30}["\']\s*\+\s*["\']', sample))
        if concat_count > 50:
            techniques.append(f'Heavy string concatenation ({concat_count} instances)')

        # Detect array-based obfuscation
        if re.search(r'\w+\[\d+\]\s*\+\s*\w+\[\d+\]', sample):
            techniques.append('Array-based string construction')

        # Detect character code manipulation
        if re.search(r'charCodeAt\s*\(', sample, re.IGNORECASE):
            techniques.append('charCodeAt() usage')

        # Check for obfuscator signatures
        if re.search(r'_0x[a-f0-9]{4,}', sample):
            techniques.append('Obfuscator signature detected (hex variable names)')

        # Check for packed/compressed code
        if 'eval(function(p,a,c,k,e,d)' in sample or 'eval(function(p,a,c,k,e,r)' in sample:
            techniques.append('Packed code (Dean Edwards packer)')

        self.results['techniques_detected'] = techniques

    def _decode_string_fromcharcode(self, content: str) -> str:
        """
        Decode String.fromCharCode() obfuscation.
        Example: String.fromCharCode(72,101,108,108,111) -> "Hello"
        """
        def replace_charcode(match):
            try:
                # Extract the numbers
                numbers_str = match.group(1)
                # Split by comma and convert to integers
                char_codes = [int(x.strip()) for x in numbers_str.split(',') if x.strip()]
                # Convert to string
                decoded = ''.join(chr(code) for code in char_codes if 0 <= code <= 0x10FFFF)
                return f'"{decoded}"'
            except (ValueError, OverflowError) as e:
                logger.debug(f"Failed to decode charCode: {e}")
                return match.group(0)

        # Pattern: String.fromCharCode(num, num, num, ...)
        pattern = r'String\.fromCharCode\s*\(\s*([\d,\s]+)\s*\)'
        decoded = re.sub(pattern, replace_charcode, content, flags=re.IGNORECASE)

        if decoded != content:
            logger.info("Decoded String.fromCharCode() patterns")

        return decoded

    def _decode_base64_in_js(self, content: str) -> str:
        """
        Decode Base64 strings in JavaScript.
        Looks for atob() calls and standalone Base64 strings.
        """
        def replace_atob(match):
            try:
                b64_str = match.group(1).strip('\'"')
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                return f'"{decoded}"'
            except Exception as e:
                logger.debug(f"Failed to decode base64: {e}")
                return match.group(0)

        # Pattern: atob("base64string")
        pattern = r'atob\s*\(\s*(["\'][^"\']+["\'])\s*\)'
        decoded = re.sub(pattern, replace_atob, content, flags=re.IGNORECASE)

        # Also try to decode long base64-looking strings
        def try_decode_b64_string(match):
            try:
                b64_str = match.group(1)
                # Only try if it looks like base64 (length > 20, valid chars)
                if len(b64_str) > 20 and re.match(r'^[A-Za-z0-9+/]+=*$', b64_str):
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                    # Only replace if decoded looks like readable text
                    if all(ord(c) < 128 and (c.isprintable() or c.isspace()) for c in decoded[:50]):
                        return f'"{decoded}"'
            except Exception:
                pass
            return match.group(0)

        # Pattern: long base64 strings in quotes
        pattern = r'"([A-Za-z0-9+/]{20,}={0,2})"'
        decoded = re.sub(pattern, try_decode_b64_string, decoded)

        if decoded != content:
            logger.info("Decoded Base64 patterns")

        return decoded

    def _decode_hex_strings(self, content: str) -> str:
        """
        Decode hex escape sequences.
        Example: \x48\x65\x6c\x6c\x6f -> Hello
        """
        def replace_hex_sequence(match):
            try:
                hex_str = match.group(0)
                # Extract all hex values
                hex_values = re.findall(r'\\x([0-9a-fA-F]{2})', hex_str)
                # Convert to string
                decoded = ''.join(chr(int(h, 16)) for h in hex_values)
                return decoded
            except (ValueError, OverflowError):
                return match.group(0)

        # Pattern: sequences of \xNN
        pattern = r'(?:\\x[0-9a-fA-F]{2})+'
        decoded = re.sub(pattern, replace_hex_sequence, content)

        if decoded != content:
            logger.info("Decoded hex escape sequences")

        return decoded

    def _decode_unicode_escapes(self, content: str) -> str:
        """
        Decode Unicode escape sequences.
        Example: \u0048\u0065\u006c\u006c\u006f -> Hello
        """
        def replace_unicode_sequence(match):
            try:
                unicode_str = match.group(0)
                # Extract all unicode values
                unicode_values = re.findall(r'\\u([0-9a-fA-F]{4})', unicode_str)
                # Convert to string
                decoded = ''.join(chr(int(u, 16)) for u in unicode_values)
                return decoded
            except (ValueError, OverflowError):
                return match.group(0)

        # Pattern: sequences of \uNNNN
        pattern = r'(?:\\u[0-9a-fA-F]{4})+'
        decoded = re.sub(pattern, replace_unicode_sequence, content)

        if decoded != content:
            logger.info("Decoded Unicode escape sequences")

        return decoded

    def _decode_url_encoding(self, content: str) -> str:
        """Decode URL-encoded strings."""
        # Look for URL-encoded strings (high percentage of % chars)
        def try_url_decode(match):
            encoded = match.group(1)
            if encoded.count('%') > len(encoded) / 10:  # At least 10% encoded
                try:
                    decoded = urllib.parse.unquote(encoded)
                    if decoded != encoded:
                        return f'"{decoded}"'
                except Exception:
                    pass
            return match.group(0)

        pattern = r'"([^"]*%[0-9a-fA-F]{2}[^"]*)"'
        decoded = re.sub(pattern, try_url_decode, content)

        if decoded != content:
            logger.info("Decoded URL encoding")

        return decoded

    def _decode_escape_unescape(self, content: str) -> str:
        """
        Decode JavaScript escape/unescape encoding.
        Example: unescape("%48%65%6c%6c%6f") -> "Hello"
        """
        def replace_unescape(match):
            try:
                escaped_str = match.group(1).strip('\'"')
                decoded = urllib.parse.unquote(escaped_str)
                return f'"{decoded}"'
            except Exception as e:
                logger.debug(f"Failed to decode unescape: {e}")
                return match.group(0)

        # Pattern: unescape("...")
        pattern = r'unescape\s*\(\s*(["\'][^"\']+["\'])\s*\)'
        decoded = re.sub(pattern, replace_unescape, content, flags=re.IGNORECASE)

        if decoded != content:
            logger.info("Decoded unescape() calls")

        return decoded

    def _simplify_string_concat(self, content: str) -> str:
        """
        Simplify string concatenation.
        Example: "hel" + "lo" + " " + "world" -> "hello world"
        """
        # Only process if there are concatenations (quick check)
        if '"+' not in content and '"  +' not in content:
            return content

        # Simple pattern: "str1" + "str2" -> "str1str2"
        def combine_strings(match):
            str1 = match.group(1)
            str2 = match.group(2)
            return f'"{str1}{str2}"'

        previous = None
        current = content
        iterations = 0

        # Keep combining until no more changes (max 10 iterations for speed)
        while current != previous and iterations < 10:
            previous = current
            # Pattern: "string1" + "string2"
            pattern = r'"([^"]*)"\s*\+\s*"([^"]*)"'
            current = re.sub(pattern, combine_strings, current)
            iterations += 1

        if current != content:
            logger.info(f"Simplified string concatenation ({iterations} passes)")

        return current

    def _extract_iocs(self, content: str):
        """Extract Indicators of Compromise from decoded content."""
        iocs_dict = {}  # Use dict to deduplicate

        # Common false positive patterns to exclude
        js_keywords = {
            'this.', 'var.', 'function.', 'return.', 'new.', 'typeof.',
            'window.', 'document.', 'console.', 'prototype.', 'constructor.',
            'length.', 'value.', 'name.', 'type.', 'id.', 'class.',
            'style.', 'innerhtml.', 'textcontent.', 'addeventlistener.',
            'eval.', 'string.', 'object.', 'array.', 'number.', 'boolean.',
            'math.', 'date.', 'json.', 'parsefloat.', 'parseint.',
            'isnan.', 'isfinite.', 'undefined.', 'null.'
        }

        # URLs (most reliable IOC)
        url_pattern = r'https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9](?::[0-9]+)?(?:/[^\s\'"<>]*)?'
        urls = re.findall(url_pattern, content, re.IGNORECASE)
        for url in urls[:100]:  # Limit to first 100
            # Skip obvious false positives
            if any(skip in url.lower() for skip in ['example.com', 'example.org', 'localhost', '127.0.0.1']):
                continue
            iocs_dict[f"URL:{url}"] = {'type': 'URL', 'value': url}

        # IP addresses (not in already-found URLs)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, content)
        for ip in ips[:50]:  # Limit to first 50
            # Skip private/reserved IPs
            parts = [int(x) for x in ip.split('.')]
            if parts[0] in [10, 127] or (parts[0] == 172 and 16 <= parts[1] <= 31) or (parts[0] == 192 and parts[1] == 168):
                continue
            if ip == '0.0.0.0' or ip == '255.255.255.255':
                continue
            # Only add if not part of a URL we already found
            if not any(ip in ioc['value'] for ioc in iocs_dict.values() if ioc['type'] == 'URL'):
                iocs_dict[f"IP:{ip}"] = {'type': 'IP', 'value': ip}

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        for email in emails[:20]:  # Limit to first 20
            if any(skip in email.lower() for skip in ['example.com', 'example.org', 'test.com']):
                continue
            iocs_dict[f"Email:{email}"] = {'type': 'Email', 'value': email}

        # Domain names - ONLY if they look suspicious and not in URLs
        # Only extract domains that appear in suspicious contexts
        suspicious_domain_contexts = [
            r'(?:connect|host|server|domain|url|site|c2|callback|beacon|exfil)[\s\'"=:,]+["\']?([a-z0-9][a-z0-9\-\.]{3,}\.[a-z]{2,})',
            r'//\s*([a-z0-9][a-z0-9\-\.]{3,}\.[a-z]{2,})',  # After //
        ]

        for pattern in suspicious_domain_contexts:
            domains = re.findall(pattern, content, re.IGNORECASE)
            for domain in domains[:20]:  # Limit per pattern
                domain_lower = domain.lower()
                # Skip if it's a JS keyword/property
                if any(domain_lower.startswith(kw) for kw in js_keywords):
                    continue
                # Skip common false positives
                if any(skip in domain_lower for skip in ['example.', 'test.', 'localhost', 'prototype.', '.length', '.value']):
                    continue
                # Must have valid TLD
                tld = domain.split('.')[-1].lower()
                if len(tld) < 2 or tld.isdigit():
                    continue
                # Skip if already in URLs
                if not any(domain in ioc['value'] for ioc in iocs_dict.values() if ioc['type'] == 'URL'):
                    iocs_dict[f"Domain:{domain}"] = {'type': 'Domain', 'value': domain}

        # Windows file paths (be very selective)
        file_pattern = r'\b[A-Z]:\\(?:Windows|Users|Program Files|ProgramData|Temp|AppData)\\[^\s\'"<>|?*]{3,50}'
        files = re.findall(file_pattern, content)
        for filepath in files[:20]:  # Limit to first 20
            iocs_dict[f"FilePath:{filepath}"] = {'type': 'File Path', 'value': filepath}

        # Convert dict back to list
        iocs = list(iocs_dict.values())
        self.results['iocs_found'] = iocs
        logger.info(f"Extracted {len(iocs)} IOCs")

    def _detect_suspicious_patterns(self, content: str):
        """Detect suspicious patterns in decoded content."""
        patterns = []

        # Suspicious function calls
        if re.search(r'eval\s*\(', content, re.IGNORECASE):
            patterns.append('Dynamic code execution (eval)')

        if re.search(r'document\.write\s*\(', content, re.IGNORECASE):
            patterns.append('DOM manipulation (document.write)')

        if re.search(r'\.createElement\s*\(', content, re.IGNORECASE):
            patterns.append('Element creation (createElement)')

        if re.search(r'XMLHttpRequest|fetch\s*\(', content, re.IGNORECASE):
            patterns.append('Network requests (XHR/fetch)')

        if re.search(r'ActiveXObject', content, re.IGNORECASE):
            patterns.append('ActiveX usage (legacy IE, potential exploit)')

        if re.search(r'WScript\.Shell|WScript\.CreateObject', content, re.IGNORECASE):
            patterns.append('Windows Script Host access')

        if re.search(r'\.Run\s*\(|\.Exec\s*\(', content, re.IGNORECASE):
            patterns.append('Command execution')

        if re.search(r'shellcode|payload|exploit', content, re.IGNORECASE):
            patterns.append('References to shellcode/payload/exploit')

        if re.search(r'vulnerability|CVE-\d{4}-\d+', content, re.IGNORECASE):
            patterns.append('Vulnerability references')

        # Heap spray patterns
        if re.search(r'([\"\']\\u[0-9a-fA-F]{4}){10,}', content):
            patterns.append('Potential heap spray (repeated Unicode)')

        self.results['suspicious_patterns'] = patterns
        logger.info(f"Detected {len(patterns)} suspicious patterns")


# Convenience function for single-use decoding
def decode_javascript(content: str) -> Dict:
    """
    Convenience function to decode JavaScript content.

    Args:
        content: JavaScript code to decode

    Returns:
        Dictionary with decoded content and analysis
    """
    decoder = ScriptDecoder()
    return decoder.analyze_script(content, 'javascript')


# Main function for testing
if __name__ == '__main__':
    # Test samples
    test_samples = [
        # String.fromCharCode test
        'var x = String.fromCharCode(72,101,108,108,111,32,87,111,114,108,100);',

        # Base64 test
        'var decoded = atob("SGVsbG8gV29ybGQ=");',

        # Hex escape test
        r'var hex = "\x48\x65\x6c\x6c\x6f";',

        # Unicode escape test
        r'var unicode = "\u0048\u0065\u006c\u006c\u006f";',

        # String concatenation test
        'var str = "Hel" + "lo" + " " + "Wor" + "ld";',

        # Combined obfuscation
        'eval(String.fromCharCode(97,108,101,114,116) + "(" + String.fromCharCode(34,72,105,34) + ")");'
    ]

    print("=" * 80)
    print("JavaScript Decoder Test Suite")
    print("=" * 80)

    for i, sample in enumerate(test_samples, 1):
        print(f"\n[Test {i}]")
        print(f"Original: {sample}")

        result = decode_javascript(sample)

        print(f"Decoded:  {result['decoded_content']}")
        print(f"Techniques: {', '.join(result['techniques_detected'])}")
        if result['iocs_found']:
            print(f"IOCs: {result['iocs_found']}")
        if result['suspicious_patterns']:
            print(f"Suspicious: {', '.join(result['suspicious_patterns'])}")
        print("-" * 80)
