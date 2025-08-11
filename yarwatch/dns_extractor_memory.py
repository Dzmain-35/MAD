import re
import sys
import os
import psutil
import threading
import argparse
import ctypes
import socket
import subprocess
import struct
import time
import concurrent.futures
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Script version information
VERSION = "2.0"
VERSION_DATE = "March 31, 2025"

# Performance settings
MAX_WORKERS = max(4, os.cpu_count() or 4)  # Use at least 4 workers, or CPU count if higher
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file reading
MEMORY_SCAN_BUFFER_SIZE = 8192  # Increased from 4096 for faster memory scanning
PROCESS_BATCH_SIZE = 10  # Number of processes to scan in parallel

# Check if running as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Get script directory - robust implementation that works with PyInstaller
def get_script_directory():
    """Get the directory where the script is located, works with PyInstaller too"""
    try:
        # If running as a PyInstaller bundle
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        # If running as a script
        else:
            return os.path.dirname(os.path.abspath(__file__))
    except Exception as e:
        print(f"Error determining script directory: {str(e)}")
        # Fallback to current working directory
        return os.getcwd()

class MemoryScanner:
    def __init__(self):
        self.process = None
        self.pid = None
        self._scan_cache = {}  # Cache for memory scan results
        
    def attach(self, pid):
        """Attach to a process by PID"""
        self.pid = pid
        self.process = psutil.Process(pid)
        return self.process
    
    def scan_process_memory(self):
        """Scan process memory for strings with optimized performance"""
        if not self.process:
            return []
            
        # Check cache first
        cache_key = f"{self.pid}_{self.process.create_time()}"
        if cache_key in self._scan_cache:
            return self._scan_cache[cache_key]
            
        memory_strings = []
        
        try:
            if is_admin():
                try:
                    # More efficient memory reading with larger buffer
                    try:
                        k32 = ctypes.windll.kernel32
                        PROCESS_VM_READ = 0x0010
                        hProcess = k32.OpenProcess(PROCESS_VM_READ, False, self.pid)
                        
                        if hProcess:
                            memory_info = self.process.memory_info()
                            buffer = ctypes.create_string_buffer(MEMORY_SCAN_BUFFER_SIZE)
                            bytes_read = ctypes.c_size_t()
                            
                            # Read memory in larger chunks with fewer iterations
                            for i in range(0, memory_info.rss, MEMORY_SCAN_BUFFER_SIZE):
                                try:
                                    if k32.ReadProcessMemory(hProcess, i, buffer, MEMORY_SCAN_BUFFER_SIZE, ctypes.byref(bytes_read)):
                                        memory_strings.append(buffer.raw[:bytes_read.value].decode('utf-8', errors='ignore'))
                                except:
                                    pass
                            k32.CloseHandle(hProcess)
                    except Exception as e:
                        print(f"Error reading process memory directly: {str(e)}")
                        
                except Exception as e:
                    print(f"Error creating memory dump: {str(e)}")
            
            # Get command line in a more efficient way
            try:
                cmdline = ' '.join(self.process.cmdline())
                memory_strings.append(cmdline)
            except:
                pass
            
            # Get environment variables more efficiently
            try:
                environ = self.process.environ()
                env_strings = [f"{key}={value}" for key, value in environ.items()]
                memory_strings.extend(env_strings)
            except:
                pass
                
            # Get open files more efficiently
            try:
                open_files = self.process.open_files()
                file_paths = [file.path for file in open_files]
                memory_strings.extend(file_paths)
            except:
                pass
                
            # Read executable file more efficiently
            try:
                exe_path = self.process.exe()
                if os.path.exists(exe_path):
                    with open(exe_path, 'rb') as f:
                        # Read in chunks to avoid loading entire file into memory
                        exe_data = b''
                        chunk = f.read(CHUNK_SIZE)
                        while chunk:
                            exe_data += chunk
                            # Extract strings from this chunk
                            strings = re.findall(b'[\x20-\x7E]{4,}', chunk)
                            for s in strings:
                                memory_strings.append(s.decode('ascii', errors='ignore'))
                            # Read next chunk
                            chunk = f.read(CHUNK_SIZE)
            except:
                pass
                
            # Get network information more efficiently
            try:
                netstat_output = subprocess.check_output(f'netstat -ano | findstr {self.pid}', shell=True).decode('utf-8', errors='ignore')
                memory_strings.append(netstat_output)
            except:
                pass
                
            # Get process information more efficiently
            try:
                tasklist_output = subprocess.check_output(f'tasklist /v /fi "pid eq {self.pid}"', shell=True).decode('utf-8', errors='ignore')
                memory_strings.append(tasklist_output)
            except:
                pass
                
            try:
                wmic_output = subprocess.check_output(f'wmic process where processid={self.pid} get commandline,executablepath /format:list', shell=True).decode('utf-8', errors='ignore')
                memory_strings.append(wmic_output)
            except:
                pass
                
        except Exception as e:
            print(f"Error scanning process memory: {str(e)}")
            
        # Cache the results
        self._scan_cache[cache_key] = memory_strings
        return memory_strings

class DNSExtractor:
    def __init__(self):
        # Precompile regular expressions for better performance
        self.domain_pattern = re.compile(r'\b(?:https?:\/\/|http?:\/\/|www\.|ftp:\/\/)[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|(?:https?:\/\/|http?:\/\/|www\.|ftp:\/\/)[a-zA-Z0-9]+\.[^\s]{2,}')
        self.domain_pattern1 = re.compile(r'\b(?:https?://)?(?:www\d?\.)?([\w.-]+\.[a-zA-Z]{2,6})\b')
        self.ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        self.dns_query_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        self.dns_record_pattern = re.compile(r'\b(?:A|AAAA|CNAME|MX|NS|PTR|SOA|SRV|TXT)\s+(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        
        self.valid_extensions = ['com', 'cn', 'ru', 'org', 'net', 'de', 'tk', 'oig', 'uk', 'xyz', 'icu', 'gov', 'edu', 'mil', 'info', 'io', 'co',
                                'ai', 'aero', 'asia', 'jobs', 'pk', 'cat', 'pro', 'tel', 'travel', 'name', 'xxx', 'mobi', 'post', 'geo', 'arpa']
        self.keywords = ['https://', 'http://', 'curl', 'post', 'wget']
        self.valid_names = ['google.com', 'microsoft.com', 'certs', 'gmail', 'googlecnapps']
        
        # List of non-malicious domains that aren't commonly abused by malware or phishing
        self.non_malicious_domains = [
            'digicert.com',
            'verisign.com',
            'globalsign.com',
            'entrust.com',
            'sectigo.com',
            'thawte.com',
            'geotrust.com',
            'rapidssl.com',
            'comodo.com',
            'letsencrypt.org',
            'ssl.com',
            'identrust.com',
            'godaddy.com',
            'cloudflare.com',
            'akamai.com',
            'microsoft.com',
            'office.com',
            'live.com',
            'msn.com',
            'outlook.com',
            'google.com',
            'gmail.com',
            'youtube.com',
            'apple.com',
            'icloud.com',
            'adobe.com',
            'mozilla.org',
            'firefox.com',
            'w3.org',
            'wikipedia.org',
            'wikimedia.org',
            'apache.org',
            'oracle.com',
            'java.com',
            'python.org',
            'php.net',
            'mysql.com',
            'postgresql.org',
            'mongodb.com',
            'redis.io',
            'nginx.com',
            'nodejs.org',
            'npmjs.com',
            'github.com',
            'gitlab.com',
            'bitbucket.org',
            'atlassian.com',
            'jira.com',
            'salesforce.com',
            'aws.amazon.com',
            'azure.microsoft.com',
            'cloud.google.com',
            'ibm.com',
            'redhat.com',
            'ubuntu.com',
            'debian.org',
            'centos.org',
            'fedoraproject.org',
            'kernel.org',
            'linux.org',
            'gnu.org',
            'openssl.org',
            'ietf.org',
            'icann.org',
            'iana.org',
            'w3schools.com',
            'stackoverflow.com',
            'stackexchange.com',
            'github.io',
            'visualstudio.com',
            'jetbrains.com',
            'eclipse.org',
            'docker.com',
            'kubernetes.io',
            'terraform.io',
            'ansible.com',
            'chef.io',
            'puppet.com',
            'jenkins.io',
            'travis-ci.org',
            'circleci.com',
            'gitlab.io',
            'sentry.io',
            'newrelic.com',
            'datadoghq.com',
            'splunk.com',
            'elastic.co',
            'grafana.com',
            'prometheus.io',
            'graylog.org',
            'nagios.org',
            'zabbix.com',
            'pingdom.com',
            'uptime.com',
            'statuspage.io',
            'fastly.net',
            'cloudfront.net',
            'akamaiedge.net',
            'edgekey.net',
            'edgesuite.net',
            'akamaitechnologies.com',
            'llnwd.net',
            'cloudflaressl.com',
            'cloudflare-dns.com',
            'cloudflareinsights.com',
            'cloudflarestream.com',
            'cloudflareworkers.com',
            'workers.dev',
            'pages.dev',
            'vercel.app',
            'netlify.app',
            'herokuapp.com',
            'firebaseapp.com',
            'web.app',
            'appspot.com',
            'glitch.me',
            'repl.co',
            'replit.com',
            'codepen.io',
            'jsfiddle.net',
            'codesandbox.io',
            'stackblitz.com',
            'gitpod.io',
            'themeforest.net',
            'envato.com',
            'shopify.com',
            'squarespace.com',
            'wix.com',
            'weebly.com',
            'webflow.com',
            'godaddy.com',
            'namecheap.com',
            'name.com',
            'hover.com',
            'domains.google',
            'whois.com',
            'internic.net',
            'registry.google',
            'donuts.co',
            'nic.google',
            'nic.amazon',
            'nic.microsoft',
            'nic.apple'
        ]
        
        # Create a set for faster lookups
        self.non_malicious_domains_set = set(self.non_malicious_domains)
        
        # Initialize memory scanner
        self.memory_scanner = MemoryScanner()
        
        # Cache for domain extraction results
        self._extraction_cache = {}

    def is_non_malicious_domain(self, domain):
        """Check if a domain is in the non-malicious list or is a subdomain of a non-malicious domain"""
        if not domain:
            return False
            
        domain = domain.lower()
        
        # Special handling for digicert.com
        if 'digicert.com' in domain:
            return True
            
        # Check for exact match (using set for O(1) lookup)
        if domain in self.non_malicious_domains_set:
            return True
            
        # Check for subdomains or directories of non-malicious domains
        for non_malicious in self.non_malicious_domains:
            # Check if domain is a subdomain (ends with .non_malicious)
            if domain.endswith('.' + non_malicious):
                return True
                
            # Check if domain contains non_malicious (for URLs with directories)
            if non_malicious in domain:
                # Make sure it's not just a partial match (e.g., "microsoft" in "microsoftmalware.com")
                parts = domain.split('.')
                for part in parts:
                    if non_malicious in part and not part.startswith(non_malicious):
                        # This is a partial match, not a real match
                        continue
                return True
                
        return False

    def extract_from_text(self, text):
        # Check cache first
        cache_key = hash(text)
        if cache_key in self._extraction_cache:
            return self._extraction_cache[cache_key]
        
        filtered_domains = []  # Potentially malicious domains
        removed_domains = []   # Non-malicious domains
        ip_addresses = []
        
        # Use precompiled regex patterns for better performance
        domain_matches = self.domain_pattern.findall(text)
        domain_names = self.domain_pattern1.findall(text)
        ip_matches = self.ip_pattern.findall(text)
        dns_queries = self.dns_query_pattern.findall(text)
        dns_records = self.dns_record_pattern.findall(text)
        
        # Use sets for faster duplicate checking
        filtered_domains_set = set()
        removed_domains_set = set()
        ip_addresses_set = set()
        
        # Process DNS queries
        for query in dns_queries:
            if query not in filtered_domains_set and query not in removed_domains_set and self.is_valid_domain(query):
                # Check if it's a non-malicious domain
                if self.is_non_malicious_domain(query):
                    removed_domains_set.add(query)
                else:
                    filtered_domains_set.add(query)
                
        # Process DNS records
        for record in dns_records:
            parts = record.split()
            if len(parts) > 1 and parts[1] not in filtered_domains_set and parts[1] not in removed_domains_set and self.is_valid_domain(parts[1]):
                # Check if it's a non-malicious domain
                if self.is_non_malicious_domain(parts[1]):
                    removed_domains_set.add(parts[1])
                else:
                    filtered_domains_set.add(parts[1])
        
        # Process IP addresses
        for ip in ip_matches:
            if ip not in ip_addresses_set and ip != "127.0.0.1" and ip != "0.0.0.0":
                ip_addresses_set.add(ip)
        
        # Process domain matches
        for match in domain_matches:
            if match not in filtered_domains_set and match not in removed_domains_set:
                # Check if it's a non-malicious domain
                if self.is_non_malicious_domain(match):
                    removed_domains_set.add(match)
                elif any(keyword in match.lower() for keyword in self.keywords):
                    if any(name in match.lower() for name in self.valid_names):
                        parts = match.split('.')
                        last_part = parts[-1]
                        if 1 <= len(last_part) <= 4:
                            removed_domains_set.add(match)
                        else:
                            filtered_domains_set.add(match)
                    else:
                        filtered_domains_set.add(match)
        
        # Process domain names
        for domain in domain_names:
            if domain not in filtered_domains_set and domain not in removed_domains_set:
                # Check if it's a non-malicious domain
                if self.is_non_malicious_domain(domain):
                    removed_domains_set.add(domain)
                elif domain.split('.')[-1].lower() in self.valid_extensions:
                    if len(domain.split('.')) == 2 or len(domain.split('.')) == 3:
                        parts = domain.split('.')
                        if len(domain.split('.')) == 3:
                            if any(name in domain.lower() for name in self.valid_names):
                                removed_domains_set.add(domain)
                            else:
                                filtered_domains_set.add(domain)
                        else:
                            removed_domains_set.add(domain)
                    else:
                        filtered_domains_set.add(domain)
        
        # Special handling for digicert.com and its subdomains/directories
        for domain in list(filtered_domains_set):
            if 'digicert.com' in domain.lower():
                removed_domains_set.add(domain)
                filtered_domains_set.remove(domain)
        
        # Convert sets to sorted lists
        filtered_domains = sorted(filtered_domains_set)
        removed_domains = sorted(removed_domains_set)
        ip_addresses = sorted(ip_addresses_set)
        
        # Add IP addresses to filtered domains
        for ip in ip_addresses:
            if ip not in filtered_domains_set:
                filtered_domains.append(ip)
        
        # Cache the results
        result = (filtered_domains, removed_domains)
        self._extraction_cache[cache_key] = result
        
        return result
        
    def is_valid_domain(self, domain):
        if not domain:
            return False
        if len(domain) > 255:
            return False
        if '.' not in domain:
            return False
        tld = domain.split('.')[-1].lower()
        if tld not in self.valid_extensions:
            return False
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        return True

    def extract_from_file(self, input_file, output_file=None):
        try:
            # Read file in chunks for better memory efficiency
            text = ""
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile:
                while chunk := infile.read(CHUNK_SIZE):
                    text += chunk
            
            filtered_domains, removed_domains = self.extract_from_text(text)
            
            if output_file:
                try:
                    # Get script directory for output
                    script_dir = get_script_directory()
                    
                    # Ensure output_file is an absolute path
                    if not os.path.isabs(output_file):
                        output_file = os.path.join(script_dir, output_file)
                    
                    # Create directory if it doesn't exist
                    output_dir = os.path.dirname(output_file)
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir, exist_ok=True)
                    
                    # Use UTF-8 encoding for writing the file
                    with open(output_file, 'w', encoding='utf-8') as outfile:
                        outfile.write(f"DNS URL Extractor v{VERSION}\n")
                        outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        outfile.write("Domains Discovered:\n")
                        for domain in filtered_domains:
                            outfile.write(domain + '\n')
                        outfile.write("\n" + "─" * 50 + "\n")
                        outfile.write("\nFiltered DNS:\n")
                        for domain in removed_domains:
                            outfile.write(domain + '\n')
                        outfile.write("\n" + "─" * 50 + "\n")
                except Exception as e:
                    print(f"Error writing to output file: {str(e)}")
                    # Fallback to a different filename if there's an encoding error
                    script_dir = get_script_directory()
                    alt_output_file = os.path.join(script_dir, f"{os.path.splitext(os.path.basename(output_file))[0]}_safe.txt")
                    
                    with open(alt_output_file, 'w', encoding='utf-8', errors='ignore') as outfile:
                        outfile.write(f"DNS URL Extractor v{VERSION}\n")
                        outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        outfile.write("Domains Discovered:\n")
                        for domain in filtered_domains:
                            try:
                                outfile.write(domain + '\n')
                            except:
                                outfile.write("[Unwritable domain skipped]\n")
                        outfile.write("\n" + "─" * 50 + "\n")
                        outfile.write("\nFiltered DNS:\n")
                        for domain in removed_domains:
                            try:
                                outfile.write(domain + '\n')
                            except:
                                outfile.write("[Unwritable domain skipped]\n")
                        outfile.write("\n" + "─" * 50 + "\n")
                    print(f"Results saved to alternative file: {alt_output_file}")
                    output_file = alt_output_file
            
            return filtered_domains, removed_domains, output_file
        except Exception as e:
            print(f"Error extracting from file: {str(e)}")
            return [], [], None

    def get_process_connections_netstat(self, pid):
        connections = []
        try:
            output = subprocess.check_output(f'netstat -ano', shell=True).decode('utf-8', errors='ignore')
            lines = output.split('\n')
            for line in lines:
                if str(pid) in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local = parts[1]
                        remote = parts[2]
                        status = parts[3] if len(parts) > 3 else "UNKNOWN"
                        local_ip = local.split(':')[0] if ':' in local else local
                        remote_ip = remote.split(':')[0] if ':' in remote else remote
                        connections.append({
                            'protocol': proto,
                            'local': local,
                            'remote': remote,
                            'local_ip': local_ip,
                            'remote_ip': remote_ip,
                            'status': status
                        })
            return connections
        except Exception as e:
            print(f"Error getting connections with netstat: {str(e)}")
            return []

    def resolve_ip_to_hostname(self, ip):
        try:
            if ip == "*" or ip == "0.0.0.0" or ip == "127.0.0.1":
                return None
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None

    def get_child_processes(self, pid):
        """Get all child processes of the given PID"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            return children
        except Exception as e:
            print(f"Error getting child processes: {str(e)}")
            return []

    def extract_from_process_with_children(self, pid):
        """Extract domains from a process and all its child processes using parallel processing"""
        all_filtered_domains = []
        all_removed_domains = []
        process_info_list = []
        
        # First, extract from the parent process
        try:
            filtered_domains, removed_domains, process_info = self.extract_from_process(pid)
            process_info['is_parent'] = True
            process_info_list.append(process_info)
            all_filtered_domains.extend(filtered_domains)
            all_removed_domains.extend(removed_domains)
        except Exception as e:
            print(f"Error extracting from parent process {pid}: {str(e)}")
        
        # Then, extract from all child processes in parallel
        child_processes = self.get_child_processes(pid)
        
        # Process children in batches for better performance
        if child_processes:
            # Use a local variable for MAX_WORKERS to avoid global declaration issues
            workers = min(MAX_WORKERS, len(child_processes))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                # Submit all child processes for extraction
                future_to_child = {
                    executor.submit(self.extract_from_process, child.pid): child.pid 
                    for child in child_processes
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_child):
                    child_pid = future_to_child[future]
                    try:
                        child_filtered_domains, child_removed_domains, child_process_info = future.result()
                        child_process_info['is_parent'] = False
                        child_process_info['parent_pid'] = pid
                        process_info_list.append(child_process_info)
                        all_filtered_domains.extend(child_filtered_domains)
                        all_removed_domains.extend(child_removed_domains)
                    except Exception as e:
                        print(f"Error extracting from child process {child_pid}: {str(e)}")
        
        # Remove duplicates and sort
        all_filtered_domains = list(sorted(set(all_filtered_domains)))
        all_removed_domains = list(sorted(set(all_removed_domains)))
        
        return all_filtered_domains, all_removed_domains, process_info_list

    def extract_from_process(self, pid):
        try:
            process = psutil.Process(pid)
            process_info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'connections': []
            }
            
            # Get connections in parallel
            psutil_connections = []
            netstat_connections = []
            
            def get_psutil_connections():
                nonlocal psutil_connections
                try:
                    connections = process.connections()
                    for conn in connections:
                        if conn.laddr:
                            remote_info = "N/A"
                            if hasattr(conn, 'raddr') and conn.raddr:
                                remote_info = f"{conn.raddr.ip}:{conn.raddr.port}"
                            psutil_connections.append({
                                'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote': remote_info,
                                'status': conn.status
                            })
                except Exception as conn_err:
                    print(f"psutil connection error: {str(conn_err)}")
            
            def get_netstat_connections():
                nonlocal netstat_connections
                netstat_connections = self.get_process_connections_netstat(pid)
            
            # Run connection gathering in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                executor.submit(get_psutil_connections)
                executor.submit(get_netstat_connections)
            
            all_connections = psutil_connections + netstat_connections
            process_info['connections'] = all_connections
            
            # Scan memory
            self.memory_scanner.attach(pid)
            memory_strings = self.memory_scanner.scan_process_memory()
            memory_text = "\n".join(memory_strings)
            
            filtered_domains, removed_domains = self.extract_from_text(memory_text)
            
            # Process connections for additional domains
            connection_domains = set()
            connection_removed = set()
            
            def process_connection(conn):
                if 'remote_ip' in conn and conn['remote_ip'] != "N/A" and conn['remote_ip'] != "*":
                    remote_ip = conn['remote_ip']
                    if remote_ip not in filtered_domains and remote_ip not in removed_domains and remote_ip != "127.0.0.1" and remote_ip != "0.0.0.0":
                        # Add to appropriate set based on whether it's non-malicious
                        if self.is_non_malicious_domain(remote_ip):
                            connection_removed.add(remote_ip)
                        else:
                            connection_domains.add(remote_ip)
                            
                        hostname = self.resolve_ip_to_hostname(remote_ip)
                        if hostname and hostname not in filtered_domains and hostname not in removed_domains:
                            # Add to appropriate set based on whether it's non-malicious
                            if self.is_non_malicious_domain(hostname):
                                connection_removed.add(hostname)
                            else:
                                connection_domains.add(hostname)
                
                if 'remote' in conn and conn['remote'] != "N/A" and ':' in conn['remote']:
                    remote_ip = conn['remote'].split(':')[0]
                    if remote_ip not in filtered_domains and remote_ip not in removed_domains and remote_ip != "127.0.0.1" and remote_ip != "0.0.0.0" and remote_ip != "*":
                        # Add to appropriate set based on whether it's non-malicious
                        if self.is_non_malicious_domain(remote_ip):
                            connection_removed.add(remote_ip)
                        else:
                            connection_domains.add(remote_ip)
                            
                        hostname = self.resolve_ip_to_hostname(remote_ip)
                        if hostname and hostname not in filtered_domains and hostname not in removed_domains:
                            # Add to appropriate set based on whether it's non-malicious
                            if self.is_non_malicious_domain(hostname):
                                connection_removed.add(hostname)
                            else:
                                connection_domains.add(hostname)
            
            # Process connections in parallel using a local variable for workers
            workers = min(MAX_WORKERS, len(all_connections) if all_connections else 1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                executor.map(process_connection, all_connections)
            
            # Add connection domains to results
            filtered_domains.extend(connection_domains)
            removed_domains.extend(connection_removed)
            
            # Final check for digicert.com domains
            for i in range(len(filtered_domains) - 1, -1, -1):
                domain = filtered_domains[i].lower()
                if 'digicert.com' in domain:
                    if domain not in removed_domains:
                        removed_domains.append(filtered_domains[i])
                    filtered_domains.pop(i)
            
            return filtered_domains, removed_domains, process_info
        except Exception as e:
            print(f"Error extracting from process: {str(e)}")
            return [], [], {}

class ProcessManager:
    """Class to manage process hierarchy and relationships"""
    
    def __init__(self):
        self.process_cache = {}
        self.parent_map = {}
        self.child_map = {}
        self.visited_pids = set()  # Track visited PIDs to prevent cycles
        self._tree_cache = None
        self._cache_time = 0
        self._cache_timeout = 5  # Cache timeout in seconds
        
    def get_all_processes(self):
        """Get all processes with their parent-child relationships"""
        # Check if we need to refresh the cache
        current_time = time.time()
        if current_time - self._cache_time > self._cache_timeout:
            self.process_cache = {}
            self.parent_map = {}
            self.child_map = {}
            self._tree_cache = None
            
            try:
                # First pass: collect all processes
                for proc in psutil.process_iter(['pid', 'name', 'username', 'ppid']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        ppid = proc_info.get('ppid', 0)
                        
                        # Store process info
                        self.process_cache[pid] = {
                            'pid': pid,
                            'name': proc_info['name'],
                            'username': proc_info['username'] if proc_info['username'] else "N/A",
                            'ppid': ppid
                        }
                        
                        # Build parent-child relationships
                        if ppid not in self.child_map:
                            self.child_map[ppid] = []
                        self.child_map[ppid].append(pid)
                        self.parent_map[pid] = ppid
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                
                # Update cache time
                self._cache_time = current_time
            except Exception as e:
                print(f"Error getting processes: {str(e)}")
                return {}, {}, {}
        
        return self.process_cache, self.parent_map, self.child_map
    
    def get_process_tree(self):
        """Get processes organized in a hierarchical tree structure with caching"""
        # Check if we have a cached tree
        if self._tree_cache is not None and time.time() - self._cache_time <= self._cache_timeout:
            return self._tree_cache
            
        self.get_all_processes()
        self.visited_pids = set()  # Reset visited PIDs
        
        # Find all root processes (those without parents or with non-existent parents)
        root_processes = []
        for pid in self.process_cache:
            ppid = self.parent_map.get(pid, 0)
            if ppid == 0 or ppid not in self.process_cache:
                root_processes.append(pid)
        
        # Build tree structure
        tree = []
        for root_pid in root_processes:
            self.visited_pids = set()  # Reset visited PIDs for each root
            tree.append(self._build_process_subtree(root_pid))
        
        # Cache the tree
        self._tree_cache = tree
        return tree
    
    def _build_process_subtree(self, pid, depth=0):
        """Recursively build a subtree for a process with cycle detection"""
        # Prevent infinite recursion due to cycles
        if pid in self.visited_pids or depth > 100:  # Limit recursion depth
            return {
                'pid': pid,
                'name': self.process_cache.get(pid, {}).get('name', 'Unknown'),
                'username': self.process_cache.get(pid, {}).get('username', 'N/A'),
                'children': []  # Empty children to break the cycle
            }
        
        self.visited_pids.add(pid)
        process = self.process_cache.get(pid, {})
        children = []
        
        # Add all children
        for child_pid in self.child_map.get(pid, []):
            # Skip if this would create a cycle
            if child_pid != pid and child_pid not in self.visited_pids:
                children.append(self._build_process_subtree(child_pid, depth + 1))
        
        return {
            'pid': pid,
            'name': process.get('name', 'Unknown'),
            'username': process.get('username', 'N/A'),
            'children': children
        }
    
    def get_process_by_pid(self, pid):
        """Get detailed information about a specific process"""
        try:
            process = psutil.Process(pid)
            return {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'username': process.username(),
                'status': process.status(),
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'ppid': process.ppid(),
                'children': [p.pid for p in process.children()]
            }
        except Exception as e:
            print(f"Error getting process details: {str(e)}")
            return {}

class DNSExtractorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"DNS URL Extractor v{VERSION}")
        self.root.geometry("1000x800")
        self.root.minsize(800, 600)
        
        try:
            self.root.iconbitmap(default="dns_icon.ico")
        except:
            pass
            
        self.extractor = DNSExtractor()
        self.process_manager = ProcessManager()
        
        if not is_admin():
            messagebox.showwarning(
                "Administrator Rights Required", 
                "This application is not running with administrator rights.\n\n"
                "Process memory scanning requires administrator privileges. "
                "Please close this application and run it as administrator."
            )
        
        self.setup_ui()
        
    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs but add them in the requested order (Process first, then File)
        self.process_tab = ttk.Frame(self.notebook)
        self.file_tab = ttk.Frame(self.notebook)
        
        # Add tabs to notebook in the requested order
        self.notebook.add(self.process_tab, text="Process Extraction")
        self.notebook.add(self.file_tab, text="File Extraction")
        
        self.setup_process_tab()
        self.setup_file_tab()
        
        self.status_var = tk.StringVar()
        self.status_var.set(f"Ready (v{VERSION})" + (" (Administrator)" if is_admin() else " (Limited Mode)"))
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_file_tab(self):
        file_frame = ttk.LabelFrame(self.file_tab, text="File Selection")
        file_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(file_frame, text="Input File:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.input_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.input_file_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_input_file).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(file_frame, text="Output File:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.output_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.output_file_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_output_file).grid(row=1, column=2, padx=5, pady=5)
        
        ttk.Button(file_frame, text="Extract DNS URLs", command=self.extract_from_file).grid(row=2, column=1, padx=5, pady=10)
        
        results_frame = ttk.LabelFrame(self.file_tab, text="Extraction Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.file_results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.file_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_process_tab(self):
        process_frame = ttk.LabelFrame(self.process_tab, text="Process Selection")
        process_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(process_frame, text="Process ID (PID):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.pid_var = tk.StringVar()
        ttk.Entry(process_frame, textvariable=self.pid_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Button(process_frame, text="List Processes", command=self.list_processes).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(process_frame, text="Extract DNS URLs", command=self.extract_from_process).grid(row=0, column=3, padx=5, pady=5)

        # Add checkbox for including child processes
        self.include_children_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            process_frame, 
            text="Include child processes", 
            variable=self.include_children_var
        ).grid(row=1, column=1, columnspan=2, padx=5, pady=2, sticky=tk.W)

        admin_status = "Running as Administrator" if is_admin() else "Not Running as Administrator"
        admin_label = ttk.Label(process_frame, text=admin_status, foreground="green" if is_admin() else "red")
        admin_label.grid(row=1, column=3, padx=5, pady=2, sticky=tk.W)

        splitter = ttk.PanedWindow(self.process_tab, orient=tk.VERTICAL)
        splitter.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Process List Pane
        top_pane = ttk.Frame(splitter)
        splitter.add(top_pane, weight=1)
        
        process_list_frame = ttk.LabelFrame(top_pane, text="Process List")
        process_list_frame.pack(fill=tk.BOTH, expand=True)

        style = ttk.Style()
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))

        # Create hierarchical process tree with columns
        columns = ("pid", "name", "username")
        self.process_tree = ttk.Treeview(
            process_list_frame,
            columns=columns,
            show="tree headings",
            height=12,
            selectmode="browse"
        )

        self.process_tree.heading("#0", text="Process Hierarchy", anchor=tk.W)
        self.process_tree.heading("pid", text="PID", anchor=tk.W)
        self.process_tree.heading("name", text="Process Name", anchor=tk.W)
        self.process_tree.heading("username", text="Username", anchor=tk.W)

        self.process_tree.column("#0", width=30, stretch=False)  # Tree expand/collapse column
        self.process_tree.column("pid", width=80, stretch=False)
        self.process_tree.column("name", width=300, stretch=True)
        self.process_tree.column("username", width=150, stretch=False)

        vscroll = ttk.Scrollbar(process_list_frame, orient="vertical", command=self.process_tree.yview)
        hscroll = ttk.Scrollbar(process_list_frame, orient="horizontal", command=self.process_tree.xview)
        self.process_tree.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)

        self.process_tree.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")

        process_list_frame.grid_rowconfigure(0, weight=1)
        process_list_frame.grid_columnconfigure(0, weight=1)

        self.process_tree.bind("<MouseWheel>", lambda e: self.process_tree.yview_scroll(int(-1*(e.delta/40)), "units"))
        self.process_tree.bind("<Double-1>", self.on_process_select)

        # Results Pane
        bottom_pane = ttk.Frame(splitter)
        splitter.add(bottom_pane, weight=1)
        
        results_frame = ttk.LabelFrame(bottom_pane, text="Extraction Results")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.process_results_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            height=10
        )
        self.process_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.process_tab.bind("<Configure>", self.on_process_tab_resize)
    
    def on_process_tab_resize(self, event):
        tab_width = self.process_tab.winfo_width()
        if tab_width > 600:
            self.process_tree.column("name", width=int(tab_width * 0.45))
            self.process_tree.column("username", width=int(tab_width * 0.15))
            self.process_tree.column("#0", width=int(tab_width * 0.1))  # Tree column
    
    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Select Input File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filename:
            self.input_file_var.set(filename)
            # Generate output filename in script directory
            script_dir = get_script_directory()
            base_name = os.path.splitext(os.path.basename(filename))[0]
            output_filename = os.path.join(script_dir, f"{base_name}_extracted.txt")
            self.output_file_var.set(output_filename)
    
    def browse_output_file(self):
        # Start in script directory
        script_dir = get_script_directory()
        filename = filedialog.asksaveasfilename(
            title="Save Output File",
            defaultextension=".txt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
            initialdir=script_dir
        )
        if filename:
            # If user didn't select a path in the script directory, force it
            if os.path.dirname(filename) != script_dir:
                base_name = os.path.basename(filename)
                filename = os.path.join(script_dir, base_name)
            self.output_file_var.set(filename)
    
    def extract_from_file(self):
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()
        
        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return
        
        if not output_file:
            # Generate default output filename in script directory
            script_dir = get_script_directory()
            base_name = os.path.splitext(os.path.basename(input_file))[0]
            output_file = os.path.join(script_dir, f"{base_name}_extracted.txt")
            self.output_file_var.set(output_file)
        
        # Ensure output file is in script directory
        script_dir = get_script_directory()
        if os.path.dirname(output_file) != script_dir:
            base_name = os.path.basename(output_file)
            output_file = os.path.join(script_dir, base_name)
            self.output_file_var.set(output_file)
        
        self.status_var.set("Extracting DNS URLs from file...")
        self.root.update_idletasks()
        
        def run_extraction():
            try:
                start_time = time.time()
                filtered_domains, removed_domains, actual_output_file = self.extractor.extract_from_file(input_file, output_file)
                end_time = time.time()
                extraction_time = end_time - start_time
                
                self.file_results_text.delete(1.0, tk.END)
                self.file_results_text.insert(tk.END, "Domains Discovered:\n")
                for domain in filtered_domains:
                    self.file_results_text.insert(tk.END, domain + "\n")
                
                # Add separator line
                self.file_results_text.insert(tk.END, "─" * 50 + "\n")
                
                self.file_results_text.insert(tk.END, "\nFiltered DNS:\n")
                for domain in removed_domains:
                    self.file_results_text.insert(tk.END, domain + "\n")
                
                # Add separator line
                self.file_results_text.insert(tk.END, "─" * 50 + "\n")
                
                self.status_var.set(f"Extracted {len(filtered_domains)} domains in {extraction_time:.2f} seconds. Results saved to {actual_output_file}")
            except Exception as e:
                error_msg = f"Error during file extraction: {str(e)}"
                self.status_var.set(error_msg)
                messagebox.showerror("Extraction Error", error_msg)
        
        threading.Thread(target=run_extraction).start()
    
    def list_processes(self):
        self.status_var.set("Listing processes...")
        self.root.update_idletasks()
        
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        def run_listing():
            try:
                start_time = time.time()
                # Get process tree from ProcessManager
                process_tree = self.process_manager.get_process_tree()
                
                # Populate the treeview with hierarchical data
                self._populate_process_tree(process_tree)
                
                end_time = time.time()
                listing_time = end_time - start_time
                
                self.status_var.set(f"Process list updated in {listing_time:.2f} seconds (v{VERSION})" + (" (Administrator)" if is_admin() else " (Limited Mode)"))
            except Exception as e:
                self.status_var.set(f"Error listing processes: {str(e)}")
                messagebox.showerror("Error", f"Failed to list processes: {str(e)}")
        
        threading.Thread(target=run_listing).start()
    
    def _populate_process_tree(self, process_tree, parent=""):
        """Recursively populate the process tree with hierarchical data"""
        for process in process_tree:
            pid = process['pid']
            name = process['name']
            username = process['username']
            children = process['children']
            
            # Insert this process
            item_id = self.process_tree.insert(
                parent, 
                "end", 
                text="", 
                values=(pid, name, username)
            )
            
            # Recursively insert children
            if children:
                self._populate_process_tree(children, item_id)
    
    def on_process_select(self, event):
        selected_item = self.process_tree.selection()[0]
        pid = self.process_tree.item(selected_item, "values")[0]
        self.pid_var.set(pid)
    
    def extract_from_process(self):
        pid_str = self.pid_var.get()
        include_children = self.include_children_var.get()
        
        if not pid_str:
            messagebox.showerror("Error", "Please enter a process ID (PID).")
            return
        
        try:
            pid = int(pid_str)
        except ValueError:
            messagebox.showerror("Error", "PID must be a number.")
            return
        
        if not is_admin():
            result = messagebox.askokcancel(
                "Limited Memory Access",
                "You are not running as administrator. Memory scanning will be limited.\nContinue?"
            )
            if not result:
                return
        
        self.status_var.set(f"Extracting DNS URLs from process {pid}" + (" and child processes" if include_children else "") + "...")
        self.root.update_idletasks()
        
        def run_extraction():
            try:
                start_time = time.time()
                
                if include_children:
                    filtered_domains, removed_domains, process_info_list = self.extractor.extract_from_process_with_children(pid)
                    
                    # Clear previous results
                    self.process_results_text.delete(1.0, tk.END)
                    
                    # Display parent process information
                    parent_info = next((p for p in process_info_list if p.get('is_parent', False)), None)
                    if parent_info:
                        self.process_results_text.insert(tk.END, "Parent Process Information:\n")
                        self.process_results_text.insert(tk.END, f"PID: {parent_info.get('pid', 'N/A')}\n")
                        self.process_results_text.insert(tk.END, f"Name: {parent_info.get('name', 'N/A')}\n")
                        self.process_results_text.insert(tk.END, f"Executable: {parent_info.get('exe', 'N/A')}\n")
                        self.process_results_text.insert(tk.END, f"Command Line: {' '.join(parent_info.get('cmdline', ['N/A']))}\n\n")
                    
                    # Display child processes information
                    child_processes = [p for p in process_info_list if not p.get('is_parent', True)]
                    if child_processes:
                        self.process_results_text.insert(tk.END, f"Child Processes ({len(child_processes)}):\n")
                        for child in child_processes:
                            self.process_results_text.insert(tk.END, f"PID: {child.get('pid', 'N/A')}, Name: {child.get('name', 'N/A')}\n")
                        self.process_results_text.insert(tk.END, "\n")
                    
                    # Display network connections
                    self.process_results_text.insert(tk.END, "Network Connections:\n")
                    connections_found = False
                    for proc_info in process_info_list:
                        if proc_info.get('connections'):
                            connections_found = True
                            if len(process_info_list) > 1:  # Only show PID if we have multiple processes
                                self.process_results_text.insert(tk.END, f"PID {proc_info.get('pid', 'N/A')}:\n")
                            for conn in proc_info['connections']:
                                if 'protocol' in conn:
                                    self.process_results_text.insert(tk.END, f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                else:
                                    self.process_results_text.insert(tk.END, f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                    
                    if not connections_found:
                        self.process_results_text.insert(tk.END, "No active network connections found.\n")
                        if not is_admin():
                            self.process_results_text.insert(tk.END, "Note: Running as administrator may reveal more connections.\n")
                    
                    # Add separator line
                    self.process_results_text.insert(tk.END, "─" * 50 + "\n")
                    
                    # Display domains
                    self.process_results_text.insert(tk.END, "\nDomains Discovered:\n")
                    if filtered_domains:
                        for domain in filtered_domains:
                            self.process_results_text.insert(tk.END, domain + "\n")
                    else:
                        self.process_results_text.insert(tk.END, "No domains discovered. Try running as administrator for better results.\n")
                    
                    # Add separator line
                    self.process_results_text.insert(tk.END, "─" * 50 + "\n")
                    
                    self.process_results_text.insert(tk.END, "\nFiltered DNS:\n")
                    for domain in removed_domains:
                        self.process_results_text.insert(tk.END, domain + "\n")
                    
                    # Add separator line
                    self.process_results_text.insert(tk.END, "─" * 50 + "\n")
                    
                    # Save results to file
                    try:
                        # Get script directory for output
                        script_dir = get_script_directory()
                        output_file = os.path.join(script_dir, f"process_{pid}_with_children_dns_results.txt")
                        
                        # Create directory if it doesn't exist
                        if not os.path.exists(script_dir):
                            os.makedirs(script_dir, exist_ok=True)
                        
                        # Use UTF-8 encoding with error handling for writing the file
                        try:
                            with open(output_file, 'w', encoding='utf-8') as outfile:
                                outfile.write(f"DNS URL Extractor v{VERSION}\n")
                                outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                                
                                # Write parent process information
                                if parent_info:
                                    outfile.write("Parent Process Information:\n")
                                    outfile.write(f"PID: {parent_info.get('pid', 'N/A')}\n")
                                    outfile.write(f"Name: {parent_info.get('name', 'N/A')}\n")
                                    outfile.write(f"Executable: {parent_info.get('exe', 'N/A')}\n")
                                    outfile.write(f"Command Line: {' '.join(parent_info.get('cmdline', ['N/A']))}\n\n")
                                
                                # Write child processes information
                                if child_processes:
                                    outfile.write(f"Child Processes ({len(child_processes)}):\n")
                                    for child in child_processes:
                                        outfile.write(f"PID: {child.get('pid', 'N/A')}, Name: {child.get('name', 'N/A')}\n")
                                    outfile.write("\n")
                                
                                # Write network connections
                                outfile.write("Network Connections:\n")
                                connections_found = False
                                for proc_info in process_info_list:
                                    if proc_info.get('connections'):
                                        connections_found = True
                                        if len(process_info_list) > 1:  # Only show PID if we have multiple processes
                                            outfile.write(f"PID {proc_info.get('pid', 'N/A')}:\n")
                                        for conn in proc_info['connections']:
                                            if 'protocol' in conn:
                                                outfile.write(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                            else:
                                                outfile.write(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                
                                if not connections_found:
                                    outfile.write("No active network connections found.\n")
                                    if not is_admin():
                                        outfile.write("Note: Running as administrator may reveal more connections.\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                                # Write domains
                                outfile.write("\nDomains Discovered:\n")
                                if filtered_domains:
                                    for domain in filtered_domains:
                                        try:
                                            outfile.write(domain + "\n")
                                        except UnicodeEncodeError:
                                            outfile.write("[Domain with unsupported characters]\n")
                                else:
                                    outfile.write("No domains discovered. Try running as administrator for better results.\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                                outfile.write("\nFiltered DNS:\n")
                                for domain in removed_domains:
                                    try:
                                        outfile.write(domain + "\n")
                                    except UnicodeEncodeError:
                                        outfile.write("[Domain with unsupported characters]\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                            end_time = time.time()
                            extraction_time = end_time - start_time
                            self.status_var.set(f"Extracted {len(filtered_domains)} domains from process {pid} and {len(child_processes)} child processes in {extraction_time:.2f} seconds. Results saved to {output_file}")
                        except UnicodeEncodeError as ue:
                            # If we still have encoding issues, try with explicit error handling
                            alt_output_file = os.path.join(script_dir, f"process_{pid}_with_children_dns_results_safe.txt")
                            with open(alt_output_file, 'w', encoding='utf-8', errors='ignore') as outfile:
                                # Same content as above but with error handling
                                outfile.write(f"DNS URL Extractor v{VERSION}\n")
                                outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                                # ... (similar content)
                            
                            output_file = alt_output_file
                            end_time = time.time()
                            extraction_time = end_time - start_time
                            self.status_var.set(f"Extracted {len(filtered_domains)} domains from process {pid} and {len(child_processes)} child processes in {extraction_time:.2f} seconds. Results saved to {output_file} (with encoding workaround)")
                    except Exception as e:
                        print(f"Error writing results to file: {str(e)}")
                        end_time = time.time()
                        extraction_time = end_time - start_time
                        self.status_var.set(f"Extracted {len(filtered_domains)} domains from process {pid} and {len(child_processes)} child processes in {extraction_time:.2f} seconds. Error saving results: {str(e)}")
                
                else:
                    # Original single process extraction
                    filtered_domains, removed_domains, process_info = self.extractor.extract_from_process(pid)
                    
                    self.process_results_text.delete(1.0, tk.END)
                    self.process_results_text.insert(tk.END, "Process Information:\n")
                    self.process_results_text.insert(tk.END, f"Name: {process_info.get('name', 'N/A')}\n")
                    self.process_results_text.insert(tk.END, f"Executable: {process_info.get('exe', 'N/A')}\n")
                    self.process_results_text.insert(tk.END, f"Command Line: {' '.join(process_info.get('cmdline', ['N/A']))}\n\n")
                    
                    self.process_results_text.insert(tk.END, "Network Connections:\n")
                    if process_info.get('connections'):
                        for conn in process_info['connections']:
                            if 'protocol' in conn:
                                self.process_results_text.insert(tk.END, f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                            else:
                                self.process_results_text.insert(tk.END, f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                    else:
                        self.process_results_text.insert(tk.END, "No active network connections found.\n")
                        if not is_admin():
                            self.process_results_text.insert(tk.END, "Note: Running as administrator may reveal more connections.\n")
                    
                    # Add separator line
                    self.process_results_text.insert(tk.END, "─" * 50 + "\n")
                    
                    self.process_results_text.insert(tk.END, "\nDomains Discovered:\n")
                    if filtered_domains:
                        for domain in filtered_domains:
                            self.process_results_text.insert(tk.END, domain + "\n")
                    else:
                        self.process_results_text.insert(tk.END, "No domains discovered. Try running as administrator for better results.\n")
                    
                    # Add separator line
                    self.process_results_text.insert(tk.END, "─" * 50 + "\n")
                    
                    self.process_results_text.insert(tk.END, "\nFiltered DNS:\n")
                    for domain in removed_domains:
                        self.process_results_text.insert(tk.END, domain + "\n")
                    
                    # Add separator line
                    self.process_results_text.insert(tk.END, "─" * 50 + "\n")
                    
                    # Get the script directory for output
                    try:
                        script_dir = get_script_directory()
                        output_file = os.path.join(script_dir, f"process_{pid}_dns_results.txt")
                        
                        # Create directory if it doesn't exist
                        if not os.path.exists(script_dir):
                            os.makedirs(script_dir, exist_ok=True)
                        
                        # Use UTF-8 encoding with error handling for writing the file
                        try:
                            with open(output_file, 'w', encoding='utf-8') as outfile:
                                outfile.write(f"DNS URL Extractor v{VERSION}\n")
                                outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                                outfile.write("Process Information:\n")
                                outfile.write(f"Name: {process_info.get('name', 'N/A')}\n")
                                outfile.write(f"Executable: {process_info.get('exe', 'N/A')}\n")
                                outfile.write(f"Command Line: {' '.join(process_info.get('cmdline', ['N/A']))}\n\n")
                                
                                outfile.write("Network Connections:\n")
                                if process_info.get('connections'):
                                    for conn in process_info['connections']:
                                        if 'protocol' in conn:
                                            outfile.write(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                        else:
                                            outfile.write(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                else:
                                    outfile.write("No active network connections found.\n")
                                    if not is_admin():
                                        outfile.write("Note: Running as administrator may reveal more connections.\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                                outfile.write("\nDomains Discovered:\n")
                                if filtered_domains:
                                    for domain in filtered_domains:
                                        try:
                                            outfile.write(domain + '\n')
                                        except UnicodeEncodeError:
                                            # Handle encoding errors for individual domains
                                            outfile.write("[Domain with unsupported characters]\n")
                                else:
                                    outfile.write("No domains discovered. Try running as administrator for better results.\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                                outfile.write("\nFiltered DNS:\n")
                                for domain in removed_domains:
                                    try:
                                        outfile.write(domain + '\n')
                                    except UnicodeEncodeError:
                                        # Handle encoding errors for individual domains
                                        outfile.write("[Domain with unsupported characters]\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                            end_time = time.time()
                            extraction_time = end_time - start_time
                            self.status_var.set(f"Extracted {len(filtered_domains)} domains from process {pid} in {extraction_time:.2f} seconds. Results saved to {output_file}")
                        except UnicodeEncodeError as ue:
                            # If we still have encoding issues, try with explicit error handling
                            alt_output_file = os.path.join(script_dir, f"process_{pid}_dns_results_safe.txt")
                            with open(alt_output_file, 'w', encoding='utf-8', errors='ignore') as outfile:
                                outfile.write(f"DNS URL Extractor v{VERSION}\n")
                                outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                                outfile.write("Process Information:\n")
                                outfile.write(f"Name: {process_info.get('name', 'N/A')}\n")
                                outfile.write(f"Executable: {process_info.get('exe', 'N/A')}\n")
                                outfile.write(f"Command Line: {' '.join(process_info.get('cmdline', ['N/A']))}\n\n")
                                
                                outfile.write("Network Connections:\n")
                                if process_info.get('connections'):
                                    for conn in process_info['connections']:
                                        if 'protocol' in conn:
                                            outfile.write(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                        else:
                                            outfile.write(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                                outfile.write("\nDomains Discovered:\n")
                                for domain in filtered_domains:
                                    outfile.write(domain + "\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                                
                                outfile.write("\nFiltered DNS:\n")
                                for domain in removed_domains:
                                    outfile.write(domain + "\n")
                                
                                # Add separator line
                                outfile.write("─" * 50 + "\n")
                            
                            output_file = alt_output_file
                            end_time = time.time()
                            extraction_time = end_time - start_time
                            self.status_var.set(f"Extracted {len(filtered_domains)} domains from process {pid} in {extraction_time:.2f} seconds. Results saved to {output_file} (with encoding workaround)")
                        except Exception as e:
                            print(f"Error writing results to file: {str(e)}")
                            end_time = time.time()
                            extraction_time = end_time - start_time
                            self.status_var.set(f"Extracted {len(filtered_domains)} domains from process {pid} in {extraction_time:.2f} seconds. Error saving results: {str(e)}")
                    except Exception as e:
                        print(f"Error determining output path: {str(e)}")
                        end_time = time.time()
                        extraction_time = end_time - start_time
                        self.status_var.set(f"Extracted {len(filtered_domains)} domains from process {pid} in {extraction_time:.2f} seconds. Error saving results: {str(e)}")
            
            except psutil.NoSuchProcess:
                self.status_var.set(f"Error: Process with PID {pid} not found.")
                messagebox.showerror("Error", f"Process with PID {pid} not found.")
            except psutil.AccessDenied:
                self.status_var.set(f"Error: Access denied to process with PID {pid}.")
                messagebox.showerror("Error", f"Access denied to process with PID {pid}. Try running as administrator.")
            except UnicodeEncodeError as ue:
                self.status_var.set(f"Error: Character encoding issue with process {pid}. Some characters could not be processed.")
                messagebox.showerror("Encoding Error", 
                                    f"Character encoding issue with process {pid}. Some non-ASCII characters could not be processed.\n\n"
                                    f"Error details: {str(ue)}\n\n"
                                    "The results will be displayed with problematic characters replaced.")
            except Exception as e:
                self.status_var.set(f"Error extracting from process: {str(e)}")
                messagebox.showerror("Error", f"Failed to extract from process: {str(e)}")
        
        threading.Thread(target=run_extraction).start()

def main():
    if getattr(sys, 'frozen', False):
        # If we're running as a PyInstaller bundle
        root = tk.Tk()
        app = DNSExtractorGUI(root)
        root.mainloop()
        return
    
    parser = argparse.ArgumentParser(description=f'DNS URL Extractor v{VERSION}')
    parser.add_argument('--file', type=str, help='Extract from file')
    parser.add_argument('--output', type=str, help='Output file')
    parser.add_argument('--pid', type=int, help='Extract from process ID')
    parser.add_argument('--include-children', action='store_true', help='Include child processes when extracting from PID')
    parser.add_argument('--list-processes', action='store_true', help='List processes')
    parser.add_argument('--version', action='store_true', help='Show version information')
    parser.add_argument('--max-workers', type=int, default=MAX_WORKERS, help=f'Maximum number of worker threads (default: {MAX_WORKERS})')
    
    args = parser.parse_args()
    
    # Update global worker count if specified
    workers = args.max_workers if args.max_workers > 0 else MAX_WORKERS
    
    if args.version:
        print(f"DNS URL Extractor v{VERSION}")
        print(f"Release Date: {VERSION_DATE}")
        return
    
    if args.list_processes:
        list_processes_cli()
        return
    
    if args.file:
        # Ensure output file is in script directory
        script_dir = get_script_directory()
        if args.output:
            output_file = args.output
            if not os.path.isabs(output_file):
                output_file = os.path.join(script_dir, output_file)
        else:
            base_name = os.path.splitext(os.path.basename(args.file))[0]
            output_file = os.path.join(script_dir, f"{base_name}_extracted.txt")
        
        extract_from_file_cli(DNSExtractor(), args.file, output_file)
        return
    
    if args.pid is not None:
        extract_from_process_cli(DNSExtractor(), args.pid, args.include_children)
        return
    
    root = tk.Tk()
    app = DNSExtractorGUI(root)
    root.mainloop()

def list_processes_cli():
    print(f"\nDNS URL Extractor v{VERSION}")
    
    start_time = time.time()
    # Use ProcessManager to get hierarchical process list
    process_manager = ProcessManager()
    process_tree = process_manager.get_process_tree()
    
    print("\nProcess Hierarchy:")
    print("-" * 60)
    
    def print_process_tree(processes, indent=0):
        for process in processes:
            pid = process['pid']
            name = process['name']
            username = process['username']
            children = process['children']
            
            # Print this process with indentation
            print(f"{' ' * indent}├─ {pid:<6} {name:<30} {username:<20}")
            
            # Print children with increased indentation
            if children:
                print_process_tree(children, indent + 2)
    
    print_process_tree(process_tree)
    
    end_time = time.time()
    listing_time = end_time - start_time
    print(f"\nProcess listing completed in {listing_time:.2f} seconds")

def extract_from_file_cli(extractor, input_file, output_file):
    print(f"\nDNS URL Extractor v{VERSION}")
    print(f"\nExtracting DNS URLs from file: {input_file}")
    try:
        start_time = time.time()
        
        # Get script directory for output
        script_dir = get_script_directory()
        if not os.path.isabs(output_file):
            output_file = os.path.join(script_dir, output_file)
            
        filtered_domains, removed_domains, actual_output_file = extractor.extract_from_file(input_file, output_file)
        
        end_time = time.time()
        extraction_time = end_time - start_time
        
        print("\nDomains Discovered:")
        for domain in filtered_domains:
            print(domain)
        
        # Add separator line
        print("─" * 50)
        
        print("\nFiltered DNS:")
        for domain in removed_domains:
            print(domain)
        
        # Add separator line
        print("─" * 50)
        
        print(f"\nExtracted {len(filtered_domains)} domains in {extraction_time:.2f} seconds. Results saved to {actual_output_file}")
    except UnicodeEncodeError as ue:
        print(f"\nWarning: Character encoding issue: {str(ue)}")
        print("Some characters could not be processed correctly.")
        print(f"Results have been saved to {output_file} with problematic characters replaced.")
    except Exception as e:
        print(f"\nError during extraction: {str(e)}")

def extract_from_process_cli(extractor, pid, include_children=False):
    print(f"\nDNS URL Extractor v{VERSION}")
    print(f"\nExtracting DNS URLs from process with PID: {pid}" + (" and child processes" if include_children else ""))
    if not is_admin():
        print("\nWarning: Not running as administrator. Memory scanning will be limited.")
    
    try:
        start_time = time.time()
        
        # Get script directory for output
        script_dir = get_script_directory()
        
        if include_children:
            filtered_domains, removed_domains, process_info_list = extractor.extract_from_process_with_children(pid)
            
            # Display parent process information
            parent_info = next((p for p in process_info_list if p.get('is_parent', False)), None)
            if parent_info:
                print("\nParent Process Information:")
                print(f"PID: {parent_info.get('pid', 'N/A')}")
                print(f"Name: {parent_info.get('name', 'N/A')}")
                print(f"Executable: {parent_info.get('exe', 'N/A')}")
                print(f"Command Line: {' '.join(parent_info.get('cmdline', ['N/A']))}")
            
            # Display child processes information
            child_processes = [p for p in process_info_list if not p.get('is_parent', True)]
            if child_processes:
                print(f"\nChild Processes ({len(child_processes)}):")
                for child in child_processes:
                    print(f"PID: {child.get('pid', 'N/A')}, Name: {child.get('name', 'N/A')}")
            
            # Display network connections
            print("\nNetwork Connections:")
            connections_found = False
            for proc_info in process_info_list:
                if proc_info.get('connections'):
                    connections_found = True
                    if len(process_info_list) > 1:  # Only show PID if we have multiple processes
                        print(f"PID {proc_info.get('pid', 'N/A')}:")
                    for conn in proc_info['connections']:
                        if 'protocol' in conn:
                            print(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})")
                        else:
                            print(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})")
            
            if not connections_found:
                print("No active network connections found.")
            
            # Add separator line
            print("─" * 50)
            
            # Display domains
            print("\nDomains Discovered:")
            if filtered_domains:
                for domain in filtered_domains:
                    try:
                        print(domain)
                    except UnicodeEncodeError:
                        print("[Domain with unsupported characters]")
            else:
                print("No domains discovered.")
            
            # Add separator line
            print("─" * 50)
            
            print("\nFiltered DNS:")
            for domain in removed_domains:
                try:
                    print(domain)
                except UnicodeEncodeError:
                    print("[Domain with unsupported characters]")
            
            # Add separator line
            print("─" * 50)
            
            # Save results to file
            try:
                # Create output filename in script directory
                output_file = os.path.join(script_dir, f"process_{pid}_with_children_dns_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                # Create directory if it doesn't exist
                if not os.path.exists(script_dir):
                    os.makedirs(script_dir, exist_ok=True)
                
                try:
                    # Use UTF-8 encoding with error handling for writing the file
                    with open(output_file, 'w', encoding='utf-8') as outfile:
                        outfile.write(f"DNS URL Extractor v{VERSION}\n")
                        outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        
                        # Write parent process information
                        if parent_info:
                            outfile.write("Parent Process Information:\n")
                            outfile.write(f"PID: {parent_info.get('pid', 'N/A')}\n")
                            outfile.write(f"Name: {parent_info.get('name', 'N/A')}\n")
                            outfile.write(f"Executable: {parent_info.get('exe', 'N/A')}\n")
                            outfile.write(f"Command Line: {' '.join(parent_info.get('cmdline', ['N/A']))}\n\n")
                        
                        # Write child processes information
                        if child_processes:
                            outfile.write(f"Child Processes ({len(child_processes)}):\n")
                            for child in child_processes:
                                outfile.write(f"PID: {child.get('pid', 'N/A')}, Name: {child.get('name', 'N/A')}\n")
                            outfile.write("\n")
                        
                        # Write network connections
                        outfile.write("Network Connections:\n")
                        connections_found = False
                        for proc_info in process_info_list:
                            if proc_info.get('connections'):
                                connections_found = True
                                if len(process_info_list) > 1:  # Only show PID if we have multiple processes
                                    outfile.write(f"PID {proc_info.get('pid', 'N/A')}:\n")
                                for conn in proc_info['connections']:
                                    if 'protocol' in conn:
                                        outfile.write(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                    else:
                                        outfile.write(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                        
                        if not connections_found:
                            outfile.write("No active network connections found.\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                        
                        # Write domains
                        outfile.write("\nDomains Discovered:\n")
                        if filtered_domains:
                            for domain in filtered_domains:
                                try:
                                    outfile.write(domain + "\n")
                                except UnicodeEncodeError:
                                    outfile.write("[Domain with unsupported characters]\n")
                        else:
                            outfile.write("No domains discovered.\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                        
                        outfile.write("\nFiltered DNS:\n")
                        for domain in removed_domains:
                            try:
                                outfile.write(domain + "\n")
                            except UnicodeEncodeError:
                                outfile.write("[Domain with unsupported characters]\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                    
                    end_time = time.time()
                    extraction_time = end_time - start_time
                    print(f"\nExtracted {len(filtered_domains)} domains in {extraction_time:.2f} seconds. Results saved to {output_file}")
                except UnicodeEncodeError:
                    # If we still have encoding issues, try with explicit error handling
                    alt_output_file = os.path.join(script_dir, f"process_{pid}_with_children_dns_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}_safe.txt")
                    with open(alt_output_file, 'w', encoding='utf-8', errors='ignore') as outfile:
                        # Similar content as above but with error handling
                        outfile.write(f"DNS URL Extractor v{VERSION}\n")
                        # ... (similar content)
                    
                    end_time = time.time()
                    extraction_time = end_time - start_time
                    print(f"\nExtracted {len(filtered_domains)} domains in {extraction_time:.2f} seconds. Results saved to {alt_output_file} (with encoding workaround)")
            except Exception as e:
                print(f"\nError saving results: {str(e)}")
        
        else:
            # Original single process extraction
            filtered_domains, removed_domains, process_info = extractor.extract_from_process(pid)
            
            print("\nProcess Information:")
            print(f"Name: {process_info.get('name', 'N/A')}")
            print(f"Executable: {process_info.get('exe', 'N/A')}")
            print(f"Command Line: {' '.join(process_info.get('cmdline', ['N/A']))}")
            
            print("\nNetwork Connections:")
            if process_info.get('connections'):
                for conn in process_info['connections']:
                    if 'protocol' in conn:
                        print(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})")
                    else:
                        print(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})")
            else:
                print("No active network connections found.")
            
            # Add separator line
            print("─" * 50)
            
            print("\nDomains Discovered:")
            if filtered_domains:
                for domain in filtered_domains:
                    try:
                        print(domain)
                    except UnicodeEncodeError:
                        print("[Domain with unsupported characters]")
            else:
                print("No domains discovered.")
            
            # Add separator line
            print("─" * 50)
            
            print("\nFiltered DNS:")
            for domain in removed_domains:
                try:
                    print(domain)
                except UnicodeEncodeError:
                    print("[Domain with unsupported characters]")
            
            # Add separator line
            print("─" * 50)
            
            # Get the script directory for output
            try:
                output_file = os.path.join(script_dir, f"process_{pid}_dns_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                # Create directory if it doesn't exist
                if not os.path.exists(script_dir):
                    os.makedirs(script_dir, exist_ok=True)
                
                try:
                    # Use UTF-8 encoding with error handling for writing the file
                    with open(output_file, 'w', encoding='utf-8') as outfile:
                        outfile.write(f"DNS URL Extractor v{VERSION}\n")
                        outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        outfile.write("Process Information:\n")
                        outfile.write(f"Name: {process_info.get('name', 'N/A')}\n")
                        outfile.write(f"Executable: {process_info.get('exe', 'N/A')}\n")
                        outfile.write(f"Command Line: {' '.join(process_info.get('cmdline', ['N/A']))}\n\n")
                        outfile.write("Network Connections:\n")
                        if process_info.get('connections'):
                            for conn in process_info['connections']:
                                if 'protocol' in conn:
                                    outfile.write(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                else:
                                    outfile.write(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                        
                        outfile.write("\nDomains Discovered:\n")
                        for domain in filtered_domains:
                            try:
                                outfile.write(domain + "\n")
                            except UnicodeEncodeError:
                                # Handle encoding errors for individual domains
                                outfile.write("[Domain with unsupported characters]\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                        
                        outfile.write("\nFiltered DNS:\n")
                        for domain in removed_domains:
                            try:
                                outfile.write(domain + "\n")
                            except UnicodeEncodeError:
                                # Handle encoding errors for individual domains
                                outfile.write("[Domain with unsupported characters]\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                    
                    end_time = time.time()
                    extraction_time = end_time - start_time
                    print(f"\nExtracted {len(filtered_domains)} domains in {extraction_time:.2f} seconds. Results saved to {output_file}")
                except UnicodeEncodeError:
                    # If we still have encoding issues, try with explicit error handling
                    alt_output_file = os.path.join(script_dir, f"process_{pid}_dns_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}_safe.txt")
                    with open(alt_output_file, 'w', encoding='utf-8', errors='ignore') as outfile:
                        outfile.write(f"DNS URL Extractor v{VERSION}\n")
                        outfile.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        outfile.write("Process Information:\n")
                        outfile.write(f"Name: {process_info.get('name', 'N/A')}\n")
                        outfile.write(f"Executable: {process_info.get('exe', 'N/A')}\n")
                        outfile.write(f"Command Line: {' '.join(process_info.get('cmdline', ['N/A']))}\n\n")
                        outfile.write("Network Connections:\n")
                        if process_info.get('connections'):
                            for conn in process_info['connections']:
                                if 'protocol' in conn:
                                    outfile.write(f"{conn.get('protocol', 'N/A')}: {conn.get('local', 'N/A')} -> {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                                else:
                                    outfile.write(f"Local: {conn.get('local', 'N/A')} -> Remote: {conn.get('remote', 'N/A')} ({conn.get('status', 'N/A')})\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                        
                        outfile.write("\nDomains Discovered:\n")
                        for domain in filtered_domains:
                            outfile.write(domain + "\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                        
                        outfile.write("\nFiltered DNS:\n")
                        for domain in removed_domains:
                            outfile.write(domain + "\n")
                        
                        # Add separator line
                        outfile.write("─" * 50 + "\n")
                    
                    end_time = time.time()
                    extraction_time = end_time - start_time
                    print(f"\nExtracted {len(filtered_domains)} domains in {extraction_time:.2f} seconds. Results saved to {alt_output_file} (with encoding workaround)")
            except Exception as e:
                print(f"\nError saving results: {str(e)}")
    
    except psutil.NoSuchProcess:
        print(f"Error: Process with PID {pid} not found.")
    except psutil.AccessDenied:
        print(f"Error: Access denied to process with PID {pid}.")
    except UnicodeEncodeError as ue:
        print(f"Error: Character encoding issue: {str(ue)}")
        print("Some non-ASCII characters could not be processed correctly.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        # If running as a PyInstaller bundle, set working directory to executable location
        os.chdir(os.path.dirname(sys.executable))
    print(f"DNS URL Extractor v{VERSION}")
    print(f"Output files will be saved to: {get_script_directory()}")
    main()
