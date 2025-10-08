# analyzer.py - Enhanced Malware Analysis Engine with Improved String Detection

import os
import hashlib
import re
import numpy as np
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

# Optional imports with fallbacks
try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False
    logger.warning("pefile not available - PE analysis will be simulation only")

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False
    logger.warning("ssdeep not available - fuzzy hashing will be simulation only")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logger.warning("python-magic not available - using basic file type detection")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not available - YARA scanning will be simulation only")


class MalwareAnalyzer:
    def __init__(self):
        if MAGIC_AVAILABLE:
            try:
                self.magic = magic.Magic(mime=True)
            except:
                self.magic = None
                logger.warning("Failed to initialize python-magic")
        else:
            self.magic = None
        
        # Comprehensive list of programming patterns that are NOT domains
        self.programming_patterns = {
            # JavaScript/Node.js patterns
            'module.exports', 'exports.module', 'require.main', 'require.cache',
            'define.amd', 'window.crypto', 'window.location', 'window.navigator',
            'document.body', 'document.head', 'document.cookie', 'document.getElementById',
            'console.log', 'console.error', 'console.warn', 'console.debug',
            'process.env', 'process.argv', 'process.cwd', 'process.exit',
            'global.window', 'global.process', 'global.console',
            'localStorage.getItem', 'localStorage.setItem', 'sessionStorage.getItem',
            'window.setTimeout', 'window.setInterval', 'window.clearTimeout',
            'document.createElement', 'document.addEventListener', 'window.addEventListener',
            'this.extend', 'this.init', 'this.prototype', 'this.constructor',
            'object.create', 'object.keys', 'object.values', 'object.assign',
            'array.push', 'array.pop', 'array.slice', 'array.splice',
            'function.call', 'function.apply', 'function.bind',
            'string.replace', 'string.split', 'string.substring',
            'math.random', 'math.floor', 'math.ceil', 'math.round',
            
            # Common programming constructs
            'e.init', 'e.extend', 'e.prototype', 'e.constructor',
            't.extend', 't.init', 't.prototype', 'n.extend', 'n.init',
            'r.extend', 'r.init', 'i.extend', 'i.init', 'o.extend',
            'a.extend', 'a.init', 'a.prototype', 's.extend', 's.init',
            
            # jQuery patterns
            'jquery.extend', 'jquery.fn', 'jquery.prototype',
            
            # Common method names that aren't domains
            'length.toString', 'value.toString', 'data.toString',
            'item.length', 'list.length', 'array.length',
            'element.style', 'element.className', 'element.innerHTML',
            
            # File extensions that get picked up
            'file.exe', 'file.dll', 'file.txt', 'file.log',
            'temp.exe', 'test.exe', 'sample.exe',
            
            # Common variable names
            'var.length', 'obj.length', 'str.length',
            'data.length', 'item.id', 'element.id'
        }
        
        # Programming keywords and method patterns
        self.programming_keywords = {
            'prototype', 'constructor', 'typeof', 'instanceof', 'extends',
            'function', 'return', 'length', 'toString', 'valueOf',
            'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
            'toLocaleString', 'charAt', 'charCodeAt', 'indexOf',
            'lastIndexOf', 'toLowerCase', 'toUpperCase', 'substr',
            'substring', 'slice', 'split', 'replace', 'match'
        }
        
        # Common legitimate domains to filter out
        self.common_legitimate_domains = {
            'microsoft.com', 'google.com', 'facebook.com', 'amazon.com',
            'apple.com', 'windows.com', 'msdn.com', 'github.com',
            'stackoverflow.com', 'jquery.com', 'bootstrap.com', 'mozilla.org',
            'w3.org', 'adobe.com', 'oracle.com', 'ibm.com', 'yahoo.com',
            'bing.com', 'live.com', 'hotmail.com', 'gmail.com', 'outlook.com',
            'cloudflare.com', 'amazonaws.com', 'googleapis.com'
        }
        
        logger.info("MalwareAnalyzer initialized")
    
    def _ensure_string(self, value):
        """Ensure value is a string, not bytes"""
        if isinstance(value, bytes):
            try:
                return value.decode('utf-8', errors='ignore')
            except:
                return str(value)
        return str(value) if value is not None else ''
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate various hashes for a file"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            
            if SSDEEP_AVAILABLE:
                try:
                    hashes['ssdeep'] = ssdeep.hash(data)
                except:
                    hashes['ssdeep'] = self._simulate_ssdeep(data)
            else:
                hashes['ssdeep'] = self._simulate_ssdeep(data)
                
            logger.info(f"Calculated hashes for {file_path}")
            return hashes
            
        except Exception as e:
            logger.error(f"Error calculating hashes for {file_path}: {str(e)}")
            raise
    
    def _simulate_ssdeep(self, data: bytes) -> str:
        """Simulate ssdeep hash when library is not available"""
        length = len(data)
        entropy = self._calculate_entropy_from_bytes(data)
        checksum = sum(data) % 1000000
        return f"24:{length}:{entropy:.0f}:{checksum}"
    
    def _calculate_entropy_from_bytes(self, data: bytes) -> float:
        """Calculate entropy from byte array"""
        if not data:
            return 0
            
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
            
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * np.log2(probability)
                
        return entropy
    
    def calculate_imphash(self, file_path: str) -> Optional[str]:
        """Calculate import hash for PE files"""
        if not PE_AVAILABLE:
            return self._simulate_imphash(file_path)
            
        try:
            pe = pefile.PE(file_path)
            imphash = pe.get_imphash()
            logger.info(f"Calculated import hash for {file_path}")
            return self._ensure_string(imphash)
        except Exception as e:
            logger.warning(f"PE analysis failed for {file_path}, using simulation: {str(e)}")
            return self._simulate_imphash(file_path)
    
    def _simulate_imphash(self, file_path: str) -> str:
        """Simulate import hash when pefile is not available"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
            return hashlib.md5(data).hexdigest()[:8]
        except:
            return "00000000"
    
    def calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            entropy = self._calculate_entropy_from_bytes(data)
            logger.info(f"Calculated entropy {entropy:.2f} for {file_path}")
            return float(entropy)
        except Exception as e:
            logger.error(f"Error calculating entropy for {file_path}: {str(e)}")
            return 0.0
    
    def detect_packing(self, file_path: str, entropy: float) -> Tuple[bool, Optional[str]]:
        """Detect if file is packed"""
        is_packed = entropy > 7.0
        packer = None
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                content = data.decode('utf-8', errors='ignore')
                
            packers = {
                'UPX': ['UPX!', 'UPX0', 'UPX1'],
                'ASPack': ['aPLib', 'ASPack'],
                'PECompact': ['PECompact', 'PEC2'],
                'VMProtect': ['VMProtect', '.vmp0', '.vmp1'],
                'Themida': ['Themida', 'WinLicense'],
                'FSG': ['FSG!', 'FSG '],
                'MEW': ['MEW ', 'NoobyProtect'],
                'Petite': ['Petite'],
                'WWPack': ['WWPack']
            }
            
            for packer_name, signatures in packers.items():
                for sig in signatures:
                    if sig in content:
                        is_packed = True
                        packer = packer_name
                        break
                if packer:
                    break
                    
            logger.info(f"Packing detection for {file_path}: packed={is_packed}, packer={packer}")
            
        except Exception as e:
            logger.warning(f"Error detecting packing for {file_path}: {str(e)}")
            
        return is_packed, self._ensure_string(packer) if packer else None
    
    def detect_language(self, file_path: str) -> str:
        """Detect programming language"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                content = data.decode('utf-8', errors='ignore')
                
            language_indicators = {
                'VBScript': ['WScript', 'CreateObject', 'Dim ', 'Set ', 'End Sub', 'End Function'],
                'JavaScript': ['function', 'var ', 'let ', 'const ', 'document.', 'window.'],
                'PowerShell': ['$_', 'Get-', 'Set-', 'New-', 'Invoke-', 'param('],
                'Batch': ['@echo', 'if exist', 'goto ', 'call ', 'set '],
                'C++': ['iostream', 'std::', 'cout', 'endl', '#include'],
                'C#': ['.NET', 'System.', 'namespace', 'using System', 'mscorlib'],
                'Visual Basic': ['Sub ', 'End Sub', 'Dim ', 'As String', 'Module'],
                'Delphi': ['unit ', 'interface', 'implementation', 'begin', 'end.'],
                'Python': ['import ', 'def ', '__init__', 'print(', 'if __name__'],
                'Go': ['package main', 'import (', 'func main', 'fmt.Print'],
                'Rust': ['fn main', 'use std::', 'let mut', 'println!'],
                'Assembly': ['mov ', 'push ', 'pop ', 'call ', 'ret', '.text']
            }
            
            max_score = 0
            detected_language = 'Unknown'
            
            for language, keywords in language_indicators.items():
                score = sum(content.lower().count(keyword.lower()) for keyword in keywords)
                if score > max_score:
                    max_score = score
                    detected_language = language
                    
            logger.info(f"Language detection for {file_path}: {detected_language}")
            return self._ensure_string(detected_language)
            
        except Exception as e:
            logger.warning(f"Error detecting language for {file_path}: {str(e)}")
            return 'Unknown'
    
    def detect_file_type(self, file_path: str) -> str:
        """Detect file type"""
        if self.magic:
            try:
                file_type = self.magic.from_file(file_path)
                logger.info(f"File type detection for {file_path}: {file_type}")
                return self._ensure_string(file_type)
            except Exception as e:
                logger.warning(f"Magic file type detection failed for {file_path}: {str(e)}")
        
        # Fallback to basic header detection
        try:
            with open(file_path, 'rb') as f:
                header = f.read(10)
            
            if header.startswith(b'MZ'):
                return 'application/x-executable'
            elif header.startswith(b'\x7fELF'):
                return 'application/x-executable'
            elif header.startswith(b'PK'):
                return 'application/zip'
            elif header.startswith(b'\x89PNG'):
                return 'image/png'
            elif header.startswith(b'\xff\xd8\xff'):
                return 'image/jpeg'
            else:
                # Check file extension for script files
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ['.vbs', '.vb']:
                    return 'text/vbscript'
                elif ext in ['.js']:
                    return 'text/javascript'
                elif ext in ['.ps1']:
                    return 'text/powershell'
                elif ext in ['.bat', '.cmd']:
                    return 'text/batch'
                elif ext in ['.py']:
                    return 'text/python'
                else:
                    return 'application/octet-stream'
                
        except Exception as e:
            logger.error(f"Error detecting file type for {file_path}: {str(e)}")
            return 'unknown'
    
    def _is_valid_domain(self, domain_candidate: str) -> bool:
        """Much stricter domain validation to filter out programming constructs"""
        domain = domain_candidate.lower().strip()
        
        # Skip if it's a known programming pattern
        if domain in self.programming_patterns:
            return False
        
        # Skip if it contains programming keywords
        parts = domain.split('.')
        for part in parts:
            if part in self.programming_keywords:
                return False
        
        # Must have exactly one dot for simple domains, or valid subdomain structure
        if domain.count('.') < 1:
            return False
            
        # Split into parts
        if len(parts) < 2:
            return False
        
        # Check for programming method patterns (object.method)
        if len(parts) == 2:
            left, right = parts
            # Common patterns that aren't domains
            programming_indicators = [
                'this', 'self', 'that', 'obj', 'object', 'element', 'item', 'data',
                'value', 'result', 'response', 'request', 'param', 'arg', 'var',
                'temp', 'test', 'sample', 'demo', 'example', 'foo', 'bar',
                'function', 'method', 'class', 'type', 'string', 'number',
                'array', 'list', 'map', 'set', 'collection', 'util', 'helper'
            ]
            
            if left in programming_indicators or right in programming_indicators:
                return False
            
            # Check if it looks like a method call (short right side)
            if len(right) <= 4 and right.isalpha():
                common_methods = [
                    'init', 'run', 'exec', 'call', 'send', 'get', 'set', 'add',
                    'pop', 'push', 'find', 'map', 'each', 'bind', 'load', 'save',
                    'open', 'close', 'read', 'write', 'copy', 'move', 'delete',
                    'create', 'update', 'insert', 'select', 'join', 'sort',
                    'parse', 'build', 'make', 'do', 'go', 'stop', 'start'
                ]
                if right in common_methods:
                    return False
        
        # Last part should be a valid TLD (2-6 characters, letters only)
        tld = parts[-1]
        if not (2 <= len(tld) <= 6 and tld.isalpha()):
            return False
        
        # Each part should be valid domain label
        for part in parts:
            if not part or len(part) > 63:  # Domain labels max 63 chars
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
            if not re.match(r'^[a-zA-Z0-9-]+$', part):
                return False
            # Part shouldn't be all numbers (except for IP addresses, which we handle separately)
            if part.isdigit():
                return False
        
        # Domain shouldn't look like a file path or have suspicious patterns
        if any(indicator in domain for indicator in ['\\', '/', ':', '%', '=', '&', '?', '#']):
            return False
        
        # Skip very short domains (likely false positives)
        if len(domain) < 4:
            return False
        
        # Skip common legitimate domains unless they're suspicious
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        if base_domain in self.common_legitimate_domains:
            return False
        
        # Additional check: domain should have at least one alphabetic character in the main part
        main_part = parts[-2] if len(parts) >= 2 else parts[0]
        if not any(c.isalpha() for c in main_part):
            return False
        
        return True
    
    def extract_all_strings(self, file_path: str, min_length: int = 4) -> List[Dict]:
        """Extract ALL printable strings from file with categorization and highlighting"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            return []
        
        # Extract all printable strings
        all_strings = []
        current_string = ""
        
        for byte in data:
            char = chr(byte)
            if char.isprintable() and char not in '\r\n\t':
                current_string += char
            else:
                if len(current_string) >= min_length:
                    all_strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            all_strings.append(current_string)
        
        # Categorize and score each string
        categorized_strings = []
        for string_val in all_strings:
            category = self._categorize_string(string_val)
            score = self._calculate_string_suspicion_score(string_val, category)
            
            categorized_strings.append({
                'value': string_val,
                'category': category,
                'suspicion_score': score,
                'length': len(string_val),
                'highlight_class': self._get_highlight_class(category, score)
            })
        
        # Sort by suspicion score (highest first)
        categorized_strings.sort(key=lambda x: x['suspicion_score'], reverse=True)
        
        logger.info(f"Extracted {len(categorized_strings)} strings from {file_path}")
        return categorized_strings
    
    def _categorize_string(self, string_val: str) -> str:
        """Categorize a string based on its content"""
        string_lower = string_val.lower()
        
        # URL check
        if re.match(r'https?://', string_val, re.IGNORECASE):
            return 'url'
        
        # IP address check
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', string_val):
            try:
                parts = [int(p) for p in string_val.split('.')]
                if all(0 <= p <= 255 for p in parts):
                    return 'ip_address'
            except:
                pass
        
        # Domain check (using our improved validation)
        if '.' in string_val and self._is_valid_domain(string_val):
            return 'domain'
        
        # Email check
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', string_val):
            return 'email'
        
        # File path check
        if re.match(r'^[A-Za-z]:\\', string_val) or '\\' in string_val:
            return 'file_path'
        
        # Registry key check
        if string_val.startswith('HKEY_'):
            return 'registry_key'
        
        # Suspicious keywords
        suspicious_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'admin', 'administrator', 'root', 'user', 'login',
            'backdoor', 'trojan', 'virus', 'malware', 'exploit',
            'shell', 'cmd', 'powershell', 'execute', 'run',
            'download', 'upload', 'install', 'payload', 'bot',
            'keylog', 'inject', 'hook', 'steal', 'grab',
            'encrypt', 'decrypt', 'crypto', 'bitcoin', 'wallet'
        ]
        
        if any(keyword in string_lower for keyword in suspicious_keywords):
            return 'suspicious'
        
        # API/Function calls
        api_patterns = [
            'CreateFile', 'WriteFile', 'ReadFile', 'CreateProcess',
            'VirtualAlloc', 'LoadLibrary', 'GetProcAddress',
            'RegOpenKey', 'RegSetValue', 'InternetOpen', 'HttpSendRequest',
            'CreateMutex', 'CreateService', 'WScript', 'CreateObject'
        ]
        
        if any(api in string_val for api in api_patterns):
            return 'api_call'
        
        # Base64-like strings
        if len(string_val) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', string_val):
            return 'base64'
        
        # Hex strings
        if len(string_val) > 8 and re.match(r'^[0-9A-Fa-f]+$', string_val):
            return 'hex'
        
        # Version numbers
        if re.match(r'^\d+\.\d+', string_val):
            return 'version'
        
        # File extensions
        if re.match(r'^\.[a-zA-Z0-9]{2,4}$', string_val):
            return 'file_extension'
        
        return 'generic'
    
    def _calculate_string_suspicion_score(self, string_val: str, category: str) -> int:
        """Calculate suspicion score for a string (0-100)"""
        score = 0
        string_lower = string_val.lower()
        
        # Base score by category
        category_scores = {
            'url': 60,
            'ip_address': 50,
            'domain': 55,
            'email': 40,
            'file_path': 30,
            'registry_key': 45,
            'suspicious': 80,
            'api_call': 70,
            'base64': 35,
            'hex': 25,
            'version': 10,
            'file_extension': 15,
            'generic': 5
        }
        
        score += category_scores.get(category, 5)
        
        # Bonus points for highly suspicious content
        high_risk_keywords = [
            'backdoor', 'trojan', 'virus', 'malware', 'exploit', 'payload',
            'keylog', 'stealer', 'grabber', 'inject', 'hook', 'rootkit',
            'ransomware', 'crypter', 'packer', 'obfuscator'
        ]
        
        for keyword in high_risk_keywords:
            if keyword in string_lower:
                score += 25
        
        # Bonus for certain file extensions in paths
        risky_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr']
        if any(ext in string_lower for ext in risky_extensions):
            score += 15
        
        # Bonus for non-standard ports in URLs
        if category == 'url' and re.search(r':\d{4,5}[/$]', string_val):
            score += 20
        
        # Bonus for suspicious domains
        if category == 'domain':
            suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.top', '.click', '.download']
            if any(tld in string_lower for tld in suspicious_tlds):
                score += 30
        
        # Penalty for very common/legitimate strings
        common_patterns = [
            'microsoft', 'windows', 'system32', 'program files',
            'copyright', 'version', 'description', 'company'
        ]
        
        if any(pattern in string_lower for pattern in common_patterns):
            score = max(0, score - 20)
        
        return min(100, max(0, score))
    
    def _get_highlight_class(self, category: str, score: int) -> str:
        """Get CSS class for highlighting based on category and score"""
        if score >= 80:
            return 'highlight-critical'
        elif score >= 60:
            return 'highlight-high'
        elif score >= 40:
            return 'highlight-medium'
        elif score >= 20:
            return 'highlight-low'
        else:
            return 'highlight-none'

    def extract_strings(self, file_path: str) -> Dict[str, List[Dict]]:
        """Extract categorized strings for backward compatibility"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Try UTF-8 first, then fall back to latin-1 which accepts all byte values
            try:
                content = data.decode('utf-8', errors='ignore')
            except:
                content = data.decode('latin-1', errors='ignore')
                
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            return {}
            
        strings = {
            'urls': [], 'ips': [], 'domains': [], 'emails': [],
            'filepaths': [], 'registry': [], 'apis': [], 'suspicious': [], 'crypto': []
        }
        
        # URL extraction
        url_pattern = r'https?://[^\s<>"{}|\\^`[\]]+'
        for match in re.finditer(url_pattern, content, re.IGNORECASE):
            url_value = self._ensure_string(match.group())
            strings['urls'].append({'value': url_value, 'confidence': 0.8})
        
        # IP extraction with validation
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for match in re.finditer(ip_pattern, content):
            ip = self._ensure_string(match.group())
            # Validate IP ranges
            try:
                parts = [int(p) for p in ip.split('.')]
                if all(0 <= p <= 255 for p in parts):
                    confidence = 0.3 if ip.startswith(('192.168.', '10.', '172.', '127.')) else 0.7
                    strings['ips'].append({'value': ip, 'confidence': confidence})
            except:
                continue
        
        # Much stricter domain extraction
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,6}(?:\.[a-zA-Z]{2,6})?\b'
        for match in re.finditer(domain_pattern, content):
            domain = self._ensure_string(match.group()).lower()
            if self._is_valid_domain(domain):
                strings['domains'].append({'value': domain, 'confidence': 0.6})
        
        # Email extraction with validation
        email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        for match in re.finditer(email_pattern, content):
            email = self._ensure_string(match.group()).lower()
            # Additional validation for email
            if '@' in email and '.' in email.split('@')[1]:
                strings['emails'].append({'value': email, 'confidence': 0.5})
        
        # File path extraction
        filepath_pattern = r'[A-Za-z]:\\(?:[^<>:"|?*\r\n]+\\)*[^<>:"|?*\r\n]+'
        for match in re.finditer(filepath_pattern, content):
            filepath = self._ensure_string(match.group())
            strings['filepaths'].append({'value': filepath, 'confidence': 0.4})
        
        # Registry key extraction
        registry_pattern = r'HKEY_[A-Z_]+\\[^<>:"|?*\r\n]+'
        for match in re.finditer(registry_pattern, content):
            regkey = self._ensure_string(match.group())
            strings['registry'].append({'value': regkey, 'confidence': 0.6})
        
        # API calls (common Windows APIs)
        api_patterns = [
            'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'CreateProcess',
            'VirtualAlloc', 'LoadLibrary', 'GetProcAddress', 'RegOpenKey', 'RegSetValue',
            'InternetOpen', 'HttpSendRequest', 'CreateMutex', 'CreateService',
            'WScript.Shell', 'CreateObject', 'GetObject', 'Shell.Application'
        ]
        for api in api_patterns:
            if api in content:
                strings['apis'].append({'value': self._ensure_string(api), 'confidence': 0.9})
        
        # Suspicious strings
        suspicious_patterns = [
            'botnet', 'keylog', 'backdoor', 'trojan', 'virus', 'malware',
            'exploit', 'payload', 'shellcode', 'rootkit', 'ransomware',
            'download', 'execute', 'install', 'persistence', 'stealth'
        ]
        for pattern in suspicious_patterns:
            if pattern.lower() in content.lower():
                strings['suspicious'].append({'value': self._ensure_string(pattern), 'confidence': 0.8})
        
        # Crypto-related strings
        crypto_patterns = [
            'AES', 'RSA', 'MD5', 'SHA1', 'SHA256', 'encrypt', 'decrypt',
            'cipher', 'crypto', 'bitcoin', 'wallet', 'base64'
        ]
        for pattern in crypto_patterns:
            if pattern.lower() in content.lower():
                strings['crypto'].append({'value': self._ensure_string(pattern), 'confidence': 0.7})
        
        total_strings = sum(len(string_list) for string_list in strings.values())
        logger.info(f"Extracted {total_strings} categorized strings from {file_path}")
        
        return strings

    def is_common_domain(self, domain: str) -> bool:
        """Check if domain is commonly legitimate"""
        return domain.lower() in self.common_legitimate_domains
    
    def classify_sample(self, sample_data: Dict) -> Dict[str, str]:
        """Classify malware sample"""
        classification = {'family': 'Unknown', 'type': 'Unknown', 'severity': 'Low'}
        
        family_indicators = {
            'VBScript Malware': ['WScript', 'CreateObject', 'Shell.Application', 'download'],
            'JavaScript Malware': ['eval', 'unescape', 'document.write', 'fromCharCode'],
            'PowerShell Malware': ['Invoke-Expression', 'DownloadString', 'EncodedCommand'],
            'Zeus': ['zeus', 'zbot', 'banking', 'formgrabber'],
            'Emotet': ['emotet', 'epoch', 'banking trojan'],
            'Trickbot': ['trickbot', 'anchor', 'banking'],
            'Ransomware': ['encrypt', 'ransom', 'bitcoin', 'decrypt', '.locked'],
            'Backdoor': ['backdoor', 'remote', 'shell', 'cmd'],
            'Keylogger': ['keylog', 'keystroke', 'capture'],
            'Botnet': ['botnet', 'bot', 'command', 'control'],
            'Downloader': ['download', 'payload', 'stage2'],
            'Rootkit': ['rootkit', 'hide', 'stealth'],
            'Adware': ['adware', 'popup', 'advertisement']
        }
        
        all_strings = []
        for string_list in sample_data.get('strings', {}).values():
            all_strings.extend([s['value'].lower() for s in string_list])
        
        # Also check the detected language for script-based classification
        language = sample_data.get('language', '').lower()
        if 'vbscript' in language or 'visual basic' in language:
            classification['type'] = 'VBScript'
            if any(indicator in ' '.join(all_strings) for indicator in ['download', 'execute', 'shell']):
                classification['family'] = 'VBScript Malware'
        elif 'javascript' in language:
            classification['type'] = 'JavaScript'
            if any(indicator in ' '.join(all_strings) for indicator in ['eval', 'unescape', 'fromcharcode']):
                classification['family'] = 'JavaScript Malware'
        elif 'powershell' in language:
            classification['type'] = 'PowerShell'
            if any(indicator in ' '.join(all_strings) for indicator in ['invoke-expression', 'downloadstring']):
                classification['family'] = 'PowerShell Malware'
        
        # Check for other family indicators
        max_score = 0
        for family, indicators in family_indicators.items():
            score = sum(1 for indicator in indicators if any(indicator in s for s in all_strings))
            if score > max_score:
                max_score = score
                classification['family'] = family
        
        # Determine file type
        file_type = sample_data.get('file_type', '')
        if 'executable' in file_type:
            classification['type'] = 'Executable'
        elif 'vbscript' in file_type or sample_data.get('name', '').endswith('.vbs'):
            classification['type'] = 'VBScript'
        elif 'javascript' in file_type or sample_data.get('name', '').endswith('.js'):
            classification['type'] = 'JavaScript'
        elif 'powershell' in file_type or sample_data.get('name', '').endswith('.ps1'):
            classification['type'] = 'PowerShell'
        
        # Determine severity
        if sample_data.get('is_packed') or len(all_strings) > 10:
            classification['severity'] = 'High'
        elif sample_data.get('strings', {}).get('suspicious', []):
            classification['severity'] = 'Medium'
            
        logger.info(f"Classification result: {classification}")
        
        # Ensure all values are strings
        return {k: self._ensure_string(v) for k, v in classification.items()}
    
    def analyze_file(self, file_path: str, filename: str) -> Dict:
        """Comprehensive file analysis with proper string handling"""
        logger.info(f"Starting analysis of {filename}")
        
        result = {'name': self._ensure_string(filename), 'file_path': self._ensure_string(file_path)}
        
        try:
            # Calculate hashes
            result.update(self.calculate_hashes(file_path))
            
            # Calculate import hash
            result['imphash'] = self.calculate_imphash(file_path)
            
            # Get file info
            result['file_size'] = int(os.path.getsize(file_path))
            result['file_type'] = self.detect_file_type(file_path)
            
            # Calculate entropy
            result['entropy'] = self.calculate_entropy(file_path)
            
            # Detect packing
            result['is_packed'], result['packer'] = self.detect_packing(file_path, result['entropy'])
            
            # Detect language
            result['language'] = self.detect_language(file_path)
            
            # Extract strings (categorized)
            result['strings'] = self.extract_strings(file_path)
            
            # Extract ALL strings for detailed analysis
            result['all_strings'] = self.extract_all_strings(file_path)
            
            # Classify sample
            result['classification'] = self.classify_sample(result)
            
            # Calculate threat score and risk level
            result['threat_score'] = self.calculate_threat_score(result)
            result['risk_level'] = self.calculate_risk_level(result['threat_score'])
            
            # Ensure all string fields are properly handled
            for key, value in result.items():
                if isinstance(value, str):
                    result[key] = self._ensure_string(value)
            
            logger.info(f"Analysis completed for {filename}")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing file {filename}: {str(e)}")
            raise
    
    def calculate_threat_score(self, sample_data: Dict) -> int:
        """Calculate threat score based on various factors"""
        score = 0
        
        # Packing adds significant risk
        if sample_data.get('is_packed'):
            score += 20
        
        # High entropy indicates encryption/obfuscation
        if sample_data.get('entropy', 0) > 7.0:
            score += 15
        
        # Suspicious strings
        suspicious_count = len(sample_data.get('strings', {}).get('suspicious', []))
        score += min(suspicious_count * 10, 30)
        
        # Network indicators
        network_count = sum(len(indicators) for key, indicators in sample_data.get('strings', {}).items() 
                           if key in ['urls', 'domains', 'ips'])
        score += min(network_count * 5, 20)
        
        # API calls
        api_count = len(sample_data.get('strings', {}).get('apis', []))
        score += min(api_count * 2, 15)
        
        # High suspicion strings from detailed analysis
        if 'all_strings' in sample_data:
            high_suspicion_count = sum(1 for s in sample_data['all_strings'] if s['suspicion_score'] >= 80)
            score += min(high_suspicion_count * 5, 20)
        
        # Script-specific scoring
        language = sample_data.get('language', '').lower()
        if any(script_lang in language for script_lang in ['vbscript', 'javascript', 'powershell']):
            score += 10  # Scripts are often used maliciously
        
        return min(int(score), 100)
    
    def calculate_risk_level(self, threat_score: int) -> str:
        """Calculate risk level from threat score"""
        if threat_score >= 80:
            return 'Critical'
        elif threat_score >= 60:
            return 'High'
        elif threat_score >= 40:
            return 'Medium'
        else:
            return 'Low'


def get_dependency_status() -> Dict[str, bool]:
    """Get status of optional dependencies"""
    return {
        'pefile': PE_AVAILABLE,
        'ssdeep': SSDEEP_AVAILABLE,
        'magic': MAGIC_AVAILABLE,
        'yara': YARA_AVAILABLE
    }
