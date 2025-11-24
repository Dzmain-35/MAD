"""
YarWatch Module - YARA-based File Scanning and Monitoring
Provides manual file scanning and detailed rule match information
"""

import os
import yara
import hashlib
import threading
from pathlib import Path
from typing import List, Dict, Optional, Callable
from datetime import datetime


class YarWatch:
    def __init__(self, yara_rules_path: str, case_manager=None):
        """
        Initialize YarWatch scanner
        
        Args:
            yara_rules_path: Path to YARA rules directory
            case_manager: Reference to CaseManager for appending scans to cases
        """
        self.yara_rules_path = yara_rules_path
        self.case_manager = case_manager
        self.yara_rules = None
        self.is_scanning = False
        self.scan_callbacks = []
        
        # Load YARA rules
        self.load_yara_rules()
    
    def load_yara_rules(self):
        """Load all YARA rules from the specified directory"""
        try:
            if not os.path.exists(self.yara_rules_path):
                print(f"ERROR: YARA rules directory does not exist: {self.yara_rules_path}")
                return False
            
            yara_files = list(Path(self.yara_rules_path).glob("*.yara")) + \
                        list(Path(self.yara_rules_path).glob("*.yar"))
            
            if not yara_files:
                print(f"WARNING: No YARA rules found in {self.yara_rules_path}")
                return False
            
            print(f"Loading {len(yara_files)} YARA rule files...")
            
            # Create a dictionary of rules for compilation
            rules_dict = {}
            for idx, yara_file in enumerate(yara_files):
                namespace = f"rule_{idx}_{yara_file.stem}"
                rules_dict[namespace] = str(yara_file)
            
            # Compile all rules
            self.yara_rules = yara.compile(filepaths=rules_dict)
            print(f"Successfully loaded {len(yara_files)} YARA rule files")
            return True
            
        except Exception as e:
            print(f"ERROR loading YARA rules: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def scan_file(self, file_path: str, add_to_case: bool = True) -> Dict:
        """
        Scan a single file with YARA rules
        
        Args:
            file_path: Path to file to scan
            add_to_case: Whether to add results to current case
            
        Returns:
            Dictionary with scan results including detailed match information
        """
        if not self.yara_rules:
            return {
                "error": "YARA rules not loaded",
                "file_path": file_path
            }
        
        if not os.path.exists(file_path):
            return {
                "error": "File not found",
                "file_path": file_path
            }
        
        try:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            print(f"\n{'='*60}")
            print(f"YarWatch Scanning: {filename}")
            print(f"{'='*60}")
            
            # Calculate hashes
            md5_hash, sha256_hash = self.calculate_hashes(file_path)
            
            # Scan with YARA
            matches = self.yara_rules.match(file_path)
            
            # Extract detailed match information
            detailed_matches = []
            for match in matches:
                match_info = {
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "strings": [],
                    "meta": dict(match.meta) if hasattr(match, 'meta') else {}
                }
                
                # Extract string matches with offsets
                for string_match in match.strings:
                    string_info = {
                        "identifier": string_match.identifier,
                        "instances": []
                    }
                    
                    for instance in string_match.instances:
                        string_info["instances"].append({
                            "offset": instance.offset,
                            "matched_data": instance.matched_data.decode('utf-8', errors='ignore')[:100],  # Limit to 100 chars
                            "length": instance.length
                        })
                    
                    match_info["strings"].append(string_info)
                
                detailed_matches.append(match_info)
            
            # Compile results
            scan_result = {
                "filename": filename,
                "file_path": file_path,
                "file_size": file_size,
                "md5": md5_hash,
                "sha256": sha256_hash,
                "scan_timestamp": datetime.now().isoformat(),
                "matches_found": len(matches),
                "detailed_matches": detailed_matches,
                "threat_detected": len(matches) > 0
            }
            
            # Print summary
            if detailed_matches:
                print(f"✓ MATCHES FOUND: {len(detailed_matches)} rule(s)")
                for match in detailed_matches:
                    print(f"  - {match['rule_name']} ({len(match['strings'])} string matches)")
            else:
                print(f"  - No YARA matches")
            
            print(f"{'='*60}\n")
            
            # Add to current case if requested
            if add_to_case and self.case_manager and self.case_manager.current_case:
                self._append_scan_to_case(scan_result)
            
            # Trigger callbacks
            for callback in self.scan_callbacks:
                callback(scan_result)
            
            return scan_result
            
        except Exception as e:
            error_result = {
                "error": str(e),
                "file_path": file_path,
                "scan_timestamp": datetime.now().isoformat()
            }
            print(f"ERROR scanning file: {e}")
            import traceback
            traceback.print_exc()
            return error_result
    
    def scan_multiple_files(self, file_paths: List[str], progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Scan multiple files with YARA rules
        
        Args:
            file_paths: List of file paths to scan
            progress_callback: Optional callback function(current, total, filename)
            
        Returns:
            List of scan result dictionaries
        """
        results = []
        total = len(file_paths)
        
        for i, file_path in enumerate(file_paths):
            if progress_callback:
                progress_callback(i + 1, total, os.path.basename(file_path))
            
            result = self.scan_file(file_path, add_to_case=True)
            results.append(result)
        
        return results
    
    def calculate_hashes(self, file_path: str) -> tuple:
        """
        Calculate MD5 and SHA256 for a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (md5, sha256)
        """
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    def _append_scan_to_case(self, scan_result: Dict):
        """
        Append scan result to current case's yarwatch_scans
        
        Args:
            scan_result: Scan result dictionary
        """
        if not self.case_manager or not self.case_manager.current_case:
            return
        
        # Initialize yarwatch_scans list if it doesn't exist
        if "yarwatch_scans" not in self.case_manager.current_case:
            self.case_manager.current_case["yarwatch_scans"] = []
        
        # Add scan result
        self.case_manager.current_case["yarwatch_scans"].append(scan_result)
        
        # Update case metadata
        case_id = self.case_manager.current_case["id"]
        case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
        self.case_manager.save_case_metadata(case_dir, self.case_manager.current_case)
        
        print(f"Scan result appended to case {case_id}")
    
    def register_scan_callback(self, callback: Callable):
        """
        Register a callback function to be called after each scan
        
        Args:
            callback: Function to call with scan result
        """
        self.scan_callbacks.append(callback)
    
    def get_rule_info(self) -> Dict:
        """
        Get information about loaded YARA rules
        
        Returns:
            Dictionary with rule statistics
        """
        if not self.yara_rules:
            return {
                "rules_loaded": False,
                "total_rules": 0
            }
        
        # Count rules (approximate - YARA doesn't expose this directly)
        yara_files = list(Path(self.yara_rules_path).glob("*.yara")) + \
                    list(Path(self.yara_rules_path).glob("*.yar"))
        
        return {
            "rules_loaded": True,
            "total_rule_files": len(yara_files),
            "rules_path": self.yara_rules_path
        }
    
    def format_match_details(self, scan_result: Dict) -> str:
        """
        Format detailed match information for display
        
        Args:
            scan_result: Scan result dictionary
            
        Returns:
            Formatted string
        """
        if "error" in scan_result:
            return f"Error: {scan_result['error']}"
        
        output = []
        output.append(f"File: {scan_result['filename']}")
        output.append(f"MD5: {scan_result['md5']}")
        output.append(f"SHA256: {scan_result['sha256']}")
        output.append(f"Size: {scan_result['file_size']} bytes")
        output.append(f"Scan Time: {scan_result['scan_timestamp']}")
        output.append("")
        
        if scan_result['matches_found'] == 0:
            output.append("No YARA matches found - File appears clean")
        else:
            output.append(f"MATCHES FOUND: {scan_result['matches_found']} rule(s)")
            output.append("=" * 60)
            
            for match in scan_result['detailed_matches']:
                output.append(f"\nRule: {match['rule_name']}")
                output.append(f"Namespace: {match['namespace']}")
                
                if match['tags']:
                    output.append(f"Tags: {', '.join(match['tags'])}")
                
                if match['meta']:
                    output.append("Metadata:")
                    for key, value in match['meta'].items():
                        output.append(f"  {key}: {value}")
                
                output.append(f"String Matches: {len(match['strings'])}")
                for string in match['strings']:
                    output.append(f"  - {string['identifier']} ({len(string['instances'])} instance(s))")
                    for idx, instance in enumerate(string['instances'][:3]):  # Show first 3 instances
                        output.append(f"    [@{instance['offset']}] {instance['matched_data'][:50]}...")
                
                output.append("")
        
        return "\n".join(output)


# Example usage for testing
if __name__ == "__main__":
    # Test the YarWatch module
    yarwatch = YarWatch(yara_rules_path=r"C:\Users\REM\Desktop\MAD\YDAMN")
    
    test_file = "sample.exe"
    if os.path.exists(test_file):
        result = yarwatch.scan_file(test_file, add_to_case=False)
        print("\nFormatted Results:")
        print(yarwatch.format_match_details(result))