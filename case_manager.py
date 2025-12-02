"""
Case Manager Module
Handles case creation, file management, and metadata collection

Requirements:
pip install requests yara-python
"""

import os
import json
import hashlib
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import requests
import yara
import tempfile
import re
from urllib.parse import urlparse

# Import from other modules (to be created)
# from utils.file_handler import FileHandler
# from thq import get_thq_family


class CaseManager:
    def __init__(self, yara_rules_path=None, case_storage_path=None, whitelist_path=None):
        """
        Initialize Case Manager
        
        Args:
            yara_rules_path: Path to YARA rules directory (if None, will look in common locations)
            case_storage_path: Path where cases will be stored (if None, uses Desktop/MAD_Cases)
            whitelist_path: Path to whitelist.txt file with SHA256 hashes
        """
        # Auto-detect YARA rules path if not provided
        if yara_rules_path is None:
            possible_paths = [
                # Absolute path (most reliable)
                r"C:\Users\REM\Desktop\MAD\YDAMN",
                # Desktop relative
                os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "YDAMN"),
                # Current directory + YDAMN (if running from MAD folder)
                os.path.join(os.getcwd(), "YDAMN"),
                # Parent directory + MAD/YDAMN
                os.path.join(os.path.dirname(os.getcwd()), "MAD", "YDAMN"),
                # Current directory + MAD/YDAMN
                os.path.join(os.getcwd(), "MAD", "YDAMN"),
                # Relative paths
                "YDAMN",
                "MAD/YDAMN",
                "./YDAMN",
                "../MAD/YDAMN"
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    yara_rules_path = os.path.abspath(path)
                    print(f"Found YARA rules at: {yara_rules_path}")
                    break
            
            if yara_rules_path is None:
                print("WARNING: YARA rules directory not found! Checked:")
                for path in possible_paths:
                    abs_path = os.path.abspath(path) if not os.path.isabs(path) else path
                    print(f"  - {abs_path} {'(exists)' if os.path.exists(path) else '(not found)'}")
                yara_rules_path = "YDAMN"  # fallback
        
        # Set case storage path to Desktop/MAD_Cases if not provided
        if case_storage_path is None:
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            case_storage_path = os.path.join(desktop_path, "MAD_Cases")
            print(f"Desktop path detected: {desktop_path}")
            print(f"Cases will be saved to: {case_storage_path}")
            
            # Verify the path exists or can be created
            if not os.path.exists(desktop_path):
                print(f"WARNING: Desktop path does not exist: {desktop_path}")
        
        # Auto-detect whitelist path
        if whitelist_path is None:
            whitelist_paths = [
                "whitelist.txt",
                os.path.join(os.getcwd(), "whitelist.txt"),
                os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "whitelist.txt"),
                r"C:\Users\REM\Desktop\MAD\whitelist.txt"
            ]
            for path in whitelist_paths:
                if os.path.exists(path):
                    whitelist_path = path
                    print(f"Found whitelist at: {whitelist_path}")
                    break
            
            if whitelist_path is None:
                print("INFO: No whitelist.txt found - all files will be analyzed")
                # Create empty whitelist file as template
                default_path = os.path.join(os.getcwd(), "whitelist.txt")
                try:
                    with open(default_path, 'w') as f:
                        f.write("# Whitelisted SHA256 hashes - one per line\n")
                        f.write("# Files matching these hashes will be marked as Benign\n")
                    print(f"Created template whitelist at: {default_path}")
                    whitelist_path = default_path
                except:
                    pass
            
        self.yara_rules_path = yara_rules_path
        self.case_storage_path = case_storage_path
        self.whitelist_path = whitelist_path
        self.vt_api_key = "93aa3b4a6ba88ba96734df3e73147f89ecfd63164f3eacd240c1ff6e592d9d49"
        self.current_case = None
        self.yara_rules = None
        self.whitelisted_hashes = set()
        
        # Ensure storage directory exists
        os.makedirs(self.case_storage_path, exist_ok=True)
        
        # Load YARA rules
        self.load_yara_rules()
        
        # Load whitelist
        self.load_whitelist()
    
    def load_yara_rules(self):
        """Load all YARA rules from the specified directory"""
        try:
            if not os.path.exists(self.yara_rules_path):
                print(f"ERROR: YARA rules directory does not exist: {self.yara_rules_path}")
                return
            
            yara_files = list(Path(self.yara_rules_path).glob("*.yara")) + \
                        list(Path(self.yara_rules_path).glob("*.yar"))
            
            if not yara_files:
                print(f"WARNING: No YARA rules found in {self.yara_rules_path}")
                print(f"Looking for files: {list(Path(self.yara_rules_path).glob('*'))}")
                return
            
            print(f"Found {len(yara_files)} YARA rule files:")
            for yf in yara_files:
                print(f"  - {yf.name}")
            
            # Create a dictionary of rules for compilation
            rules_dict = {}
            for idx, yara_file in enumerate(yara_files):
                namespace = f"rule_{idx}_{yara_file.stem}"
                rules_dict[namespace] = str(yara_file)
            
            # Compile all rules
            print("Compiling YARA rules...")
            self.yara_rules = yara.compile(filepaths=rules_dict)
            print(f"Successfully loaded {len(yara_files)} YARA rule files")
            
        except Exception as e:
            print(f"ERROR loading YARA rules: {e}")
            import traceback
            traceback.print_exc()
            self.yara_rules = None
    
    def load_whitelist(self):
        """Load whitelisted SHA256 hashes from whitelist.txt"""
        if not self.whitelist_path or not os.path.exists(self.whitelist_path):
            print("No whitelist loaded")
            return
        
        try:
            with open(self.whitelist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        # Validate it's a SHA256 (64 hex characters)
                        if len(line) == 64 and all(c in '0123456789abcdefABCDEF' for c in line):
                            self.whitelisted_hashes.add(line.lower())
            
            print(f"Loaded {len(self.whitelisted_hashes)} whitelisted hashes")
            
        except Exception as e:
            print(f"Error loading whitelist: {e}")
    
    def create_case(self, file_paths: List[str]) -> Dict:
        """
        Create a new case with initial file uploads
        
        Args:
            file_paths: List of file paths to analyze
            
        Returns:
            Case information dictionary
        """
        # Generate case ID
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        case_dir = os.path.join(self.case_storage_path, case_id)
        files_dir = os.path.join(case_dir, "files")
        
        # Create case directories
        os.makedirs(files_dir, exist_ok=True)
        
        # Initialize case data
        case_data = {
            "id": case_id,
            "created": datetime.now().isoformat(),
            "status": "ACTIVE",
            "files": [],
            "total_threats": 0,
            "total_vt_hits": 0,
            "iocs": {
                "urls": [],
                "ips": [],
                "domains": []
            }
        }
        
        # Process each file
        for file_path in file_paths:
            file_info = self.process_file(file_path, files_dir, case_id)
            case_data["files"].append(file_info)
            
            # Update case statistics - count as threat if YARA match OR THQ match OR VT hits
            # BUT NOT if whitelisted
            if not file_info.get("whitelisted", False):
                has_yara = len(file_info["yara_matches"]) > 0
                has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                has_vt = file_info["vt_hits"] > 0
                
                if has_yara or has_thq or has_vt:
                    case_data["total_threats"] += 1
                case_data["total_vt_hits"] += file_info["vt_hits"]
        
        # Save case metadata
        self.save_case_metadata(case_dir, case_data)
        
        self.current_case = case_data
        return case_data
    
    def add_files_to_case(self, file_paths: List[str]) -> Dict:
        """
        Add files to existing case
        
        Args:
            file_paths: List of file paths to add
            
        Returns:
            Updated case information
        """
        if not self.current_case:
            raise ValueError("No active case. Create a case first.")
        
        case_id = self.current_case["id"]
        case_dir = os.path.join(self.case_storage_path, case_id)
        files_dir = os.path.join(case_dir, "files")
        
        # Process each new file
        for file_path in file_paths:
            file_info = self.process_file(file_path, files_dir, case_id)
            self.current_case["files"].append(file_info)
            
            # Update case statistics - count as threat if YARA match OR THQ match OR VT hits
            # BUT NOT if whitelisted
            if not file_info.get("whitelisted", False):
                has_yara = len(file_info["yara_matches"]) > 0
                has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                has_vt = file_info["vt_hits"] > 0
                
                if has_yara or has_thq or has_vt:
                    self.current_case["total_threats"] += 1
                self.current_case["total_vt_hits"] += file_info["vt_hits"]
        
        # Update case metadata
        self.save_case_metadata(case_dir, self.current_case)
        
        return self.current_case
    
    def process_file(self, file_path: str, storage_dir: str, case_id: str) -> Dict:
        """
        Process a single file: copy, hash, scan, and collect metadata
        
        Args:
            file_path: Original file path
            storage_dir: Directory to store the file
            case_id: Current case ID
            
        Returns:
            File information dictionary
        """
        filename = os.path.basename(file_path)
        print(f"\n{'='*60}")
        print(f"Processing file: {filename}")
        print(f"{'='*60}")
        
        # Copy file to case storage
        dest_path = os.path.join(storage_dir, filename)
        shutil.copy2(file_path, dest_path)
        print(f"Copied to: {dest_path}")
        
        # Calculate hashes
        print("Calculating hashes...")
        md5, sha256, imphash = self.calculate_hashes(dest_path)
        print(f"  MD5: {md5}")
        print(f"  SHA256: {sha256}")
        print(f"  IMPHASH: {imphash}")
        
        # Get file size
        file_size = os.path.getsize(dest_path)
        print(f"File size: {file_size} bytes")
        
        # Scan with YARA
        yara_matches = self.scan_with_yara(dest_path)
        
        # Query VirusTotal
        print("Querying VirusTotal...")
        vt_hits, vt_family = self.query_virustotal(sha256)
        print(f"  VT Hits: {vt_hits}")
        print(f"  VT Family: {vt_family}")
        
        # Get THQ Family using MD5
        print("Querying ThreatHQ...")
        thq_family = self.get_thq_family(md5)
        print(f"  THQ Family: {thq_family}")
        
        # Check if file is whitelisted
        is_whitelisted = sha256.lower() in self.whitelisted_hashes
        if is_whitelisted:
            print(f"✓ File is WHITELISTED")

        # Calculate threat score
        threat_score = self.calculate_threat_score(yara_matches, vt_hits)
        threat_level = self.get_threat_level(threat_score)
        print(f"Threat Score: {threat_score} ({threat_level})")

        # Compile file information
        file_info = {
            "filename": filename,
            "original_path": file_path,
            "storage_path": dest_path,
            "md5": md5,
            "sha256": sha256,
            "imphash": imphash,
            "file_size": file_size,
            "whitelisted": is_whitelisted,
            "yara_matches": yara_matches,
            "vt_hits": vt_hits,
            "vt_family": vt_family,
            "thq_family": thq_family,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "timestamp": datetime.now().isoformat(),
            "case_id": case_id
        }
        
        # Save individual file details
        self.save_file_details(storage_dir, filename, file_info)
        print(f"{'='*60}\n")
        
        return file_info
    
    def calculate_hashes(self, file_path: str) -> tuple:
        """
        Calculate MD5, SHA256, and IMPHASH for a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (md5, sha256, imphash)
        """
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        # Read file and calculate hashes
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        # IMPHASH calculation (requires pefile for PE files)
        imphash = "N/A"
        try:
            import pefile
            pe = pefile.PE(file_path)
            imphash = pe.get_imphash()
        except:
            pass  # Not a PE file or pefile not installed
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest(), imphash
    
    def scan_with_yara(self, file_path: str) -> List[str]:
        """
        Scan file with YARA rules
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of matched rule names
        """
        if not self.yara_rules:
            print(f"WARNING: No YARA rules loaded, skipping scan for {file_path}")
            return []
        
        try:
            print(f"Scanning {os.path.basename(file_path)} with YARA...")
            matches = self.yara_rules.match(file_path)
            
            if matches:
                print(f"  ✓ YARA MATCHES FOUND: {[m.rule for m in matches]}")
            else:
                print(f"  - No YARA matches")
            
            return [match.rule for match in matches]
        except Exception as e:
            print(f"YARA scan error for {file_path}: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def query_virustotal(self, sha256: str) -> tuple:
        """
        Query VirusTotal for file information
        
        Args:
            sha256: SHA256 hash of the file
            
        Returns:
            Tuple of (detection_count, most_common_family)
        """
        if not self.vt_api_key:
            return 0, "Unknown"
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": self.vt_api_key}
            
            print(f"  Querying VT for SHA256: {sha256[:16]}...")
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                
                # Extract most common family name
                results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
                families = []
                for engine, result in results.items():
                    if result.get("category") == "malicious":
                        result_name = result.get("result", "")
                        if result_name:
                            # Clean up family name
                            family = result_name.split('.')[0].split(':')[0].split('/')[0]
                            if family and len(family) > 2:
                                families.append(family)
                
                # Get most common family
                if families:
                    from collections import Counter
                    most_common = Counter(families).most_common(1)[0][0]
                else:
                    most_common = "Unknown"
                
                print(f"    VT Response: {malicious} detections, Family: {most_common}")
                return malicious, most_common
            
            elif response.status_code == 404:
                print(f"    VT Response: File not found in database")
                return 0, "Unknown"
            
            elif response.status_code == 429:
                print(f"    VT Response: Rate limit exceeded, skipping VT check")
                return 0, "RateLimited"
            
            else:
                print(f"    VT Response: Error {response.status_code}")
                return 0, "Unknown"
            
        except Exception as e:
            print(f"    VirusTotal query error: {e}")
        
        return 0, "Unknown"
    
    def get_thq_family(self, md5_hash: str) -> str:
        """
        Get THQ family classification using ThreatHQ API
        
        Args:
            md5_hash: MD5 hash of the file
            
        Returns:
            THQ family name
        """
        try:
            thquser = "088611ff43c14dcbb8ce10af714872b4"
            thqpass = "5ea7fba6ebff4158a0469b47a49c2895"
            url = f"https://www.threathq.com/apiv1/threat/search/?malwareArtifactMD5={md5_hash}"
            
            response = requests.post(url, auth=(thquser, thqpass), timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                threats = data.get("data", {}).get("threats", [])
                for threat in threats:
                    block_set = threat.get("blockSet", [])
                    for block in block_set:
                        malware_family = block.get("malwareFamily", {})
                        family_name = malware_family.get("familyName")
                        if family_name:
                            return family_name
            
            return "Unknown"
            
        except Exception as e:
            print(f"ThreatHQ query error: {e}")
            return "Unknown"
    
    def calculate_threat_score(self, yara_matches: List[str], vt_hits: int) -> int:
        """
        Calculate threat score based on YARA matches and VT hits
        
        Args:
            yara_matches: List of YARA rule matches
            vt_hits: Number of VirusTotal detections
            
        Returns:
            Threat score (0-100)
        """
        score = 0
        
        # YARA matches contribute up to 40 points
        score += min(len(yara_matches) * 20, 40)
        
        # VT hits contribute up to 60 points
        if vt_hits > 0:
            # Scale VT hits: 1-10 hits = 20pts, 11-30 = 40pts, 31+ = 60pts
            if vt_hits >= 31:
                score += 60
            elif vt_hits >= 11:
                score += 40
            elif vt_hits >= 1:
                score += 20
        
        return min(score, 100)
    
    def get_threat_level(self, score: int) -> str:
        """
        Convert threat score to threat level

        Args:
            score: Threat score (0-100)

        Returns:
            Threat level string
        """
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 30:
            return "Medium"
        elif score > 0:
            return "Low"
        return "Clean"

    def download_file_from_url(self, url: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Download a file from a URL to a temporary location

        Args:
            url: URL to download from
            timeout: Request timeout in seconds

        Returns:
            Tuple of (success, file_path, error_message)
        """
        try:
            print(f"Downloading file from URL: {url}")

            # Parse URL to get filename
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path)

            # If no filename in URL, generate one
            if not filename or '.' not in filename:
                filename = f"downloaded_file_{datetime.now().strftime('%Y%m%d%H%M%S')}.bin"

            # Create temporary file
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, filename)

            # Download file with streaming
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = requests.get(url, headers=headers, timeout=timeout, stream=True)
            response.raise_for_status()

            # Write to temporary file
            with open(temp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            file_size = os.path.getsize(temp_path)
            print(f"Successfully downloaded {file_size} bytes to {temp_path}")

            # Add URL to IOCs if we have a current case
            if self.current_case:
                self.add_ioc("urls", url)

            return True, temp_path, ""

        except requests.exceptions.Timeout:
            error_msg = f"Timeout downloading from {url}"
            print(f"ERROR: {error_msg}")
            return False, "", error_msg

        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to download from {url}: {str(e)}"
            print(f"ERROR: {error_msg}")
            return False, "", error_msg

        except Exception as e:
            error_msg = f"Unexpected error downloading from {url}: {str(e)}"
            print(f"ERROR: {error_msg}")
            return False, "", error_msg

    def create_case_from_urls(self, urls: List[str]) -> Tuple[Dict, List[str]]:
        """
        Create a new case by downloading files from URLs

        Args:
            urls: List of URLs to download

        Returns:
            Tuple of (case_data, list of error messages)
        """
        downloaded_files = []
        errors = []

        # Download all files first
        for url in urls:
            success, file_path, error = self.download_file_from_url(url)
            if success:
                downloaded_files.append(file_path)
            else:
                errors.append(f"{url}: {error}")

        # Create case with downloaded files if any succeeded
        if downloaded_files:
            case_data = self.create_case(downloaded_files)

            # Clean up temporary files
            for file_path in downloaded_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except:
                    pass

            return case_data, errors
        else:
            raise ValueError("Failed to download any files from provided URLs")

    def add_files_from_urls_to_case(self, urls: List[str]) -> Tuple[Dict, List[str]]:
        """
        Add files to existing case by downloading from URLs

        Args:
            urls: List of URLs to download

        Returns:
            Tuple of (updated case_data, list of error messages)
        """
        if not self.current_case:
            raise ValueError("No active case. Create a case first.")

        downloaded_files = []
        errors = []

        # Download all files first
        for url in urls:
            success, file_path, error = self.download_file_from_url(url)
            if success:
                downloaded_files.append(file_path)
            else:
                errors.append(f"{url}: {error}")

        # Add files to case if any succeeded
        if downloaded_files:
            case_data = self.add_files_to_case(downloaded_files)

            # Clean up temporary files
            for file_path in downloaded_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except:
                    pass

            return case_data, errors
        else:
            return self.current_case, errors

    def add_ioc(self, ioc_type: str, value: str):
        """
        Add an IOC (Indicator of Compromise) to the current case

        Args:
            ioc_type: Type of IOC ('urls', 'ips', 'domains')
            value: IOC value
        """
        if not self.current_case:
            return

        if ioc_type not in self.current_case.get("iocs", {}):
            if "iocs" not in self.current_case:
                self.current_case["iocs"] = {"urls": [], "ips": [], "domains": []}

        # Avoid duplicates
        if value not in self.current_case["iocs"][ioc_type]:
            self.current_case["iocs"][ioc_type].append(value)

            # Save updated metadata
            case_id = self.current_case["id"]
            case_dir = os.path.join(self.case_storage_path, case_id)
            self.save_case_metadata(case_dir, self.current_case)

    def extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs (URLs, IPs, domains) from text

        Args:
            text: Text to extract IOCs from

        Returns:
            Dictionary with lists of URLs, IPs, and domains
        """
        iocs = {"urls": [], "ips": [], "domains": []}

        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        iocs["urls"].extend(urls)

        # IP pattern (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        # Filter out invalid IPs
        valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
        iocs["ips"].extend(valid_ips)

        # Domain pattern (basic)
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(domain_pattern, text.lower())
        iocs["domains"].extend(domains)

        # Remove duplicates
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        return iocs
    
    def format_file_details(self, file_info: Dict) -> str:
        """
        Format file details for display
        
        Args:
            file_info: File information dictionary
            
        Returns:
            Formatted string for display
        """
        yara_display = ", ".join(file_info["yara_matches"]) if file_info["yara_matches"] else "None"
        
        details = f"""File Details:
==================================================================
File Name: {file_info['filename']}
MD5: {file_info['md5']}
SHA256: {file_info['sha256']}
File Size: {file_info['file_size']} bytes
==================================================================
IMPHASH: {file_info['imphash']}
YARA Rule: {yara_display}
VT Hits: {file_info['vt_hits']}
THQ Family: {file_info['thq_family']}
Threat Score: {file_info['threat_score']} ({file_info['threat_level']})
=================================================================="""
        
        return details
    
    def get_yara_display_text(self, yara_matches: List[str]) -> str:
        """
        Format YARA matches for GUI display (e.g., "RuleName +2")
        
        Args:
            yara_matches: List of YARA rule matches
            
        Returns:
            Formatted string for display
        """
        if not yara_matches:
            return "No Matches"
        
        if len(yara_matches) == 1:
            return yara_matches[0]
        
        return f"{yara_matches[0]} +{len(yara_matches) - 1}"
    
    def save_case_metadata(self, case_dir: str, case_data: Dict):
        """
        Save case metadata to JSON file

        Args:
            case_dir: Case directory path
            case_data: Case data dictionary
        """
        metadata_path = os.path.join(case_dir, "case_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(case_data, f, indent=4)

    def save_case_notes(self, case_dir: str, notes: str):
        """
        Save case notes to text file

        Args:
            case_dir: Case directory path
            notes: Notes text content
        """
        notes_path = os.path.join(case_dir, "case_notes.txt")
        with open(notes_path, 'w', encoding='utf-8') as f:
            f.write(notes)

    def save_file_details(self, storage_dir: str, filename: str, file_info: Dict):
        """
        Save individual file details to JSON
        
        Args:
            storage_dir: Directory where file is stored
            filename: Name of the file
            file_info: File information dictionary
        """
        details_path = os.path.join(storage_dir, f"{filename}_details.json")
        with open(details_path, 'w') as f:
            json.dump(file_info, f, indent=4)
    
    def get_current_case(self) -> Optional[Dict]:
        """
        Get current active case
        
        Returns:
            Current case dictionary or None
        """
        return self.current_case
    
    def get_file_info(self, filename: str) -> Optional[Dict]:
        """
        Get information for a specific file in current case
        
        Args:
            filename: Name of the file
            
        Returns:
            File info dictionary or None
        """
        if not self.current_case:
            return None
        
        for file_info in self.current_case["files"]:
            if file_info["filename"] == filename:
                return file_info
        
        return None


# Example usage for testing
if __name__ == "__main__":
    # Initialize case manager
    manager = CaseManager()
    
    # Create a new case with files
    test_files = ["sample.exe"]  # Replace with actual test files
    
    if os.path.exists(test_files[0]):
        case = manager.create_case(test_files)
        print(f"Created case: {case['id']}")
        
        # Display file details
        for file_info in case["files"]:
            print("\n" + manager.format_file_details(file_info))
    else:
        print("Test file not found. Please provide a valid file path.")