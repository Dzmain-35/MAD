"""
Process Monitor Module - Real-time Process Monitoring with YARA Scanning
ENHANCED VERSION with Memory String Extraction

Monitors new processes, scans them with YARA using plugin architecture, and extracts strings for analysis
Now includes direct memory reading similar to Process Hacker
"""

import os
import psutil
import threading
import time
import yara
import re
from pathlib import Path
from typing import Dict, List, Optional, Callable, Set
from datetime import datetime

# Enhanced memory extraction support
try:
    from .memory_string_extractor import MemoryStringExtractor
    MEMORY_EXTRACTION_AVAILABLE = True
except (ImportError, OSError) as e:
    MEMORY_EXTRACTION_AVAILABLE = False
    print(f"WARNING: Memory string extractor not available ({e}). Using fallback method.")


class ProcessMonitor:
    def __init__(self, yara_rules_path: str):
        """
        Initialize Process Monitor
        
        Args:
            yara_rules_path: Path to YARA rules directory
        """
        self.yara_rules_path = yara_rules_path
        self.yara_rules = None
        self.is_monitoring = False
        self.monitor_thread = None
        self.known_pids: Set[int] = set()
        self.process_callbacks = []
        self.scan_new_processes = True
        
        # Track all monitored processes
        self.monitored_processes: Dict[int, Dict] = {}
        
        # Initialize memory extractor if available
        if MEMORY_EXTRACTION_AVAILABLE:
            try:
                # Enable verbose mode to see what's happening
                self.memory_extractor = MemoryStringExtractor(verbose=True)
                print("✓ Memory string extractor initialized (verbose mode enabled)")
            except Exception as e:
                print(f"ERROR: Failed to initialize memory extractor: {e}")
                self.memory_extractor = None
        else:
            self.memory_extractor = None
            print("ℹ Memory string extractor not available, using fallback method")
        
        # Load YARA rules
        self.load_yara_rules()
        
        # Initialize with current processes
        self._initialize_known_processes()
    
    def load_yara_rules(self):
        """Load all YARA rules from the specified directory"""
        try:
            if not os.path.exists(self.yara_rules_path):
                print(f"WARNING: YARA rules directory does not exist: {self.yara_rules_path}")
                return False
            
            yara_files = list(Path(self.yara_rules_path).glob("*.yara")) + \
                        list(Path(self.yara_rules_path).glob("*.yar"))
            
            if not yara_files:
                print(f"WARNING: No YARA rules found in {self.yara_rules_path}")
                return False
            
            # Create a dictionary of rules for compilation
            rules_dict = {}
            for idx, yara_file in enumerate(yara_files):
                namespace = f"rule_{idx}_{yara_file.stem}"
                rules_dict[namespace] = str(yara_file)
            
            # Compile all rules
            self.yara_rules = yara.compile(filepaths=rules_dict)
            print(f"Process Monitor: Loaded {len(yara_files)} YARA rule files")
            return True
            
        except Exception as e:
            print(f"ERROR loading YARA rules for Process Monitor: {e}")
            return False
    
    def _initialize_known_processes(self):
        """Initialize the set of known PIDs with currently running processes"""
        try:
            for proc in psutil.process_iter(['pid']):
                self.known_pids.add(proc.info['pid'])
            print(f"Initialized with {len(self.known_pids)} known processes")
        except Exception as e:
            print(f"Error initializing known processes: {e}")
    
    def start_monitoring(self):
        """Start monitoring for new processes"""
        if self.is_monitoring:
            print("Process monitoring already active")
            return False
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("Process monitoring started")
        return True
    
    def stop_monitoring(self):
        """Stop monitoring for new processes"""
        if not self.is_monitoring:
            return False
        
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("Process monitoring stopped")
        return True
    
    def _monitor_loop(self):
        """Main monitoring loop - runs in separate thread"""
        print("Process monitoring loop started")
        
        while self.is_monitoring:
            try:
                current_pids = set()
                
                # Get all current processes
                for proc in psutil.process_iter(['pid']):
                    current_pids.add(proc.info['pid'])
                
                # Find new processes
                new_pids = current_pids - self.known_pids
                
                for pid in new_pids:
                    try:
                        # Get process info
                        proc_info = self.get_process_info(pid)
                        
                        # Check if proc_info is None before accessing it
                        if proc_info is None:
                            continue
                        
                        if self.scan_new_processes:
                            # Scan new process with plugin-based approach
                            scan_result = self.scan_process_plugins(pid)
                            
                            # Check if scan_result is valid
                            if scan_result:
                                proc_info["scan_results"] = scan_result
                                
                                # Check if malware detected
                                if scan_result.get("matches_found"):
                                    proc_info["threat_detected"] = True
                                    proc_info["yara_matches"] = 1
                                    proc_info["yara_rule"] = scan_result.get("rule", "Unknown")
                                    print(f"⚠️ THREAT DETECTED in new process: PID {pid} - {proc_info.get('name', 'Unknown')}")
                                    if scan_result.get("rule"):
                                        print(f"   Rule: {scan_result['rule']}")
                        
                        # Store monitored process
                        self.monitored_processes[pid] = proc_info
                        
                        # Trigger callbacks
                        for callback in self.process_callbacks:
                            try:
                                callback(proc_info)
                            except Exception as cb_error:
                                print(f"Error in callback: {cb_error}")
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    except Exception as e:
                        print(f"Error processing PID {pid}: {e}")
                
                # Update known PIDs
                self.known_pids = current_pids
                
                # Sleep before next check
                time.sleep(0.5)  # Check every 500ms
            
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(1)
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """
        Get detailed information about a process
        
        Args:
            pid: Process ID
            
        Returns:
            Dictionary with process information or None if error
        """
        try:
            proc = psutil.Process(pid)
            
            # Get basic info
            with proc.oneshot():
                info = {
                    "pid": pid,
                    "ppid": proc.ppid(),
                    "name": proc.name(),
                    "exe": proc.exe() if proc.exe() else "N/A",
                    "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "N/A",
                    "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                    "status": proc.status(),
                    "username": proc.username() if proc.username() else "N/A",
                }
                
                # Get resource usage
                try:
                    info["cpu_percent"] = proc.cpu_percent(interval=0.1)
                    info["memory_info"] = proc.memory_info()._asdict()
                    info["num_threads"] = proc.num_threads()
                except:
                    pass
                
                # Get parent process
                try:
                    parent = proc.parent()
                    info["parent_pid"] = parent.pid if parent else None
                    info["parent_name"] = parent.name() if parent else None
                except:
                    info["parent_pid"] = None
                    info["parent_name"] = None
                
                # Get network connections
                try:
                    connections = proc.connections()
                    info["connections"] = []
                    for conn in connections[:10]:  # Limit to 10 connections
                        conn_info = {
                            "fd": conn.fd,
                            "family": str(conn.family),
                            "type": str(conn.type),
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            "status": conn.status
                        }
                        info["connections"].append(conn_info)
                except:
                    info["connections"] = []
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            return None
        except Exception as e:
            print(f"Error getting process info for PID {pid}: {e}")
            return None
    
    def scan_process_plugins(self, pid: int) -> Optional[Dict]:
        """
        Scan a process using plugin-based approach (like your pid_plugins.py)
        
        Args:
            pid: Process ID to scan
            
        Returns:
            Dictionary with scan results or None if error
        """
        try:
            context = {
                "pid": int(pid),
                "results": {
                    "target_type": "pid",
                    "target": str(pid),
                    "timestamp": datetime.now().isoformat(),
                    "matches_found": False,
                },
            }
            
            # Plugin 1: Get process info
            self._pid_process_info_plugin(context)
            
            # Plugin 2: YARA memory scan
            self._pid_yara_memory_plugin(context)
            
            # Plugin 3: Fallback YARA scan if no memory match
            if not context["results"].get("matches_found"):
                self._pid_yara_fallback_plugin(context)
            
            # Plugin 4: Calculate threat score
            self._pid_threat_score_plugin(context)
            
            return context["results"]
        except Exception as e:
            print(f"Error in scan_process_plugins for PID {pid}: {e}")
            return None
    
    def _pid_process_info_plugin(self, ctx):
        """Plugin to get basic process info"""
        pid = ctx["pid"]
        results = ctx["results"]
        
        try:
            proc = psutil.Process(pid)
            results["process_name"] = proc.name()
            results["exe_path"] = proc.exe() if proc.exe() else "N/A"
            results["create_time"] = datetime.fromtimestamp(proc.create_time()).isoformat()
        except Exception as e:
            results["process_name"] = "unknown"
            results["exe_path"] = "N/A"
            results["create_time"] = None
    
    def _pid_yara_memory_plugin(self, ctx):
        """Plugin to scan process memory with YARA"""
        pid = ctx["pid"]
        results = ctx["results"]
        
        if not self.yara_rules:
            return
        
        try:
            # Scan process memory directly
            matches = self.yara_rules.match(pid=pid)
            
            if matches:
                m = matches[0]
                results["rule"] = m.rule
                results["matches_found"] = True
                
                # Extract matched strings
                matched_strings = set()
                for string_match in m.strings:
                    for instance in string_match.instances:
                        try:
                            matched_strings.add(instance.matched_data.decode('utf-8', errors='ignore'))
                        except:
                            continue
                
                results["strings"] = sorted(list(matched_strings))[:10]  # First 10 for display
                print(f"[YARA] Memory scan matched rule: {m.rule} for PID {pid}")
                
        except Exception as e:
            print(f"[ERROR] YARA memory scan failed for PID {pid}: {e}")
    
    def _pid_yara_fallback_plugin(self, ctx):
        """Plugin to do fallback YARA scan on extracted strings"""
        pid = ctx["pid"]
        results = ctx["results"]
        
        if results.get("matches_found"):
            return  # Already found match in memory
        
        try:
            # Extract strings from process
            all_strings = self.extract_strings_from_process(pid, min_length=4, limit=5000)
            
            if not all_strings:
                return
            
            # Write strings to temp file
            os.makedirs("temp", exist_ok=True)
            temp_path = os.path.join("temp", f"pid_{pid}_fallback.txt")
            
            with open(temp_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write("\n".join(all_strings))
            
            # Scan with YARA
            if self.yara_rules:
                matches = self.yara_rules.match(filepath=temp_path)
                
                if matches:
                    m = matches[0]
                    results["rule"] = m.rule
                    results["matches_found"] = True
                    
                    # Get matched strings from file
                    matched_strings = set()
                    for string_match in m.strings:
                        for instance in string_match.instances:
                            try:
                                matched_strings.add(instance.matched_data.decode('utf-8', errors='ignore'))
                            except:
                                continue
                    
                    results["strings"] = sorted(list(matched_strings))[:10]
                    print(f"[YARA] Fallback scan matched rule: {m.rule} for PID {pid}")
            
            # Clean up temp file
            try:
                os.remove(temp_path)
            except:
                pass
                
        except Exception as e:
            print(f"[ERROR] Fallback YARA scan failed for PID {pid}: {e}")
    
    def _pid_threat_score_plugin(self, ctx):
        """Plugin to calculate threat score"""
        results = ctx["results"]
        
        score = 0
        reasons = []
        
        rule = results.get("rule", "No_YARA_Hit")
        strings = results.get("strings", [])
        
        if rule != "No_YARA_Hit":
            score += 60
            reasons.append(f"Matched YARA rule '{rule}' (+60)")
        
        if len(strings) > 5:
            score += 20
            reasons.append(f"Multiple string matches ({len(strings)}) (+20)")
        elif len(strings) > 0:
            score += 10
            reasons.append(f"String matches found (+10)")
        
        # Determine level
        if score >= 60:
            level = "Critical"
        elif score >= 40:
            level = "High"
        elif score >= 20:
            level = "Medium"
        else:
            level = "Low"
        
        results["threat_score"] = score
        results["risk_level"] = level
        results["score_reasons"] = reasons
    
    def scan_process(self, pid: int) -> Optional[Dict]:
        """
        Scan a process with YARA rules (legacy method for compatibility)
        
        Args:
            pid: Process ID to scan
            
        Returns:
            Dictionary with scan results or error dict
        """
        try:
            result = self.scan_process_plugins(pid)
            if result is None:
                return {"error": f"Failed to scan PID {pid}"}
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def extract_strings_from_process(self, pid: int, min_length: int = 4, limit: int = 1000) -> List[str]:
        """
        Extract printable strings from process memory (ENHANCED VERSION)
        
        This now uses direct memory reading similar to Process Hacker when available.
        Falls back to file-based extraction if memory extraction is not available.
        
        Args:
            pid: Process ID
            min_length: Minimum string length
            limit: Maximum number of strings to return
            
        Returns:
            List of extracted strings
        """
        if MEMORY_EXTRACTION_AVAILABLE and self.memory_extractor:
            return self._extract_strings_from_memory(pid, min_length, limit)
        else:
            return self._extract_strings_from_file(pid, min_length, limit)
    
    def _extract_strings_from_memory(self, pid: int, min_length: int, limit: int) -> List[str]:
        """
        Enhanced memory-based string extraction using Windows API
        """
        try:
            # Extract strings from process memory
            results = self.memory_extractor.extract_strings_from_memory(
                pid=pid,
                min_length=min_length,
                max_strings=limit,
                include_unicode=True,
                filter_regions=['private', 'image', 'mapped']  # Scan all region types
            )
            
            # Combine all string types into a single list
            all_strings = []
            
            # Prioritize interesting strings
            interesting = self.memory_extractor.get_interesting_strings(results)
            
            # Add in priority order: suspicious, network, commands, crypto, files
            priority_order = ['suspicious', 'network', 'commands', 'crypto', 'files']
            for category in priority_order:
                all_strings.extend(interesting.get(category, []))
            
            # Add remaining strings from categorized results
            for str_type in ['urls', 'paths', 'ips', 'registry']:
                all_strings.extend(results['strings'].get(str_type, []))
            
            # Add general ASCII/Unicode strings if we need more
            if len(all_strings) < limit:
                remaining = limit - len(all_strings)
                all_strings.extend(list(results['strings'].get('ascii', []))[:remaining // 2])
                all_strings.extend(list(results['strings'].get('unicode', []))[:remaining // 2])
            
            # Remove duplicates while preserving order
            seen = set()
            unique_strings = []
            for s in all_strings:
                if s not in seen and len(s) >= min_length:
                    seen.add(s)
                    unique_strings.append(s)
                    if len(unique_strings) >= limit:
                        break
            
            return unique_strings
            
        except Exception as e:
            print(f"Error in memory-based string extraction for PID {pid}: {e}")
            # Fallback to file-based extraction
            return self._extract_strings_from_file(pid, min_length, limit)
    
    def _extract_strings_from_file(self, pid: int, min_length: int, limit: int) -> List[str]:
        """
        Fallback file-based string extraction (original method)
        """
        try:
            proc = psutil.Process(pid)
            
            strings = set()
            
            # Extract from executable
            exe_path = proc.exe()
            if exe_path and os.path.exists(exe_path):
                pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
                
                try:
                    with open(exe_path, 'rb') as f:
                        chunk_size = 1024 * 1024  # 1MB chunks
                        while len(strings) < limit:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            
                            found = pattern.findall(chunk)
                            for s in found:
                                try:
                                    decoded = s.decode('utf-8', errors='ignore')
                                    strings.add(decoded)
                                    if len(strings) >= limit:
                                        break
                                except:
                                    pass
                except Exception as e:
                    print(f"Error reading executable: {e}")
            
            # Get command line and environment
            try:
                cmdline = proc.cmdline()
                for arg in cmdline:
                    if len(arg) >= min_length:
                        strings.add(arg)
                
                try:
                    environ = proc.environ()
                    for key, value in environ.items():
                        if len(value) >= min_length:
                            strings.add(f"{key}={value}")
                except:
                    pass
                    
            except Exception as e:
                print(f"Error extracting runtime strings: {e}")
            
            return list(strings)[:limit]
            
        except Exception as e:
            print(f"Error extracting strings from PID {pid}: {e}")
            return []
    
    def get_process_memory_details(self, pid: int) -> Dict:
        """
        Get detailed memory information for a process
        
        Args:
            pid: Process ID
            
        Returns:
            Dictionary with memory region details
        """
        if not MEMORY_EXTRACTION_AVAILABLE or not self.memory_extractor:
            return {"error": "Memory extraction not available"}
        
        try:
            # Extract with minimal strings to get region info
            results = self.memory_extractor.extract_strings_from_memory(
                pid=pid,
                min_length=4,
                max_strings=100,  # Just a few for quick scan
                include_unicode=False,
                filter_regions=['private', 'image', 'mapped']
            )
            
            # Format memory regions
            memory_info = {
                'total_regions': len(results['memory_regions']),
                'total_bytes': results['total_bytes_scanned'],
                'regions_by_type': {},
                'regions': results['memory_regions']
            }
            
            # Count regions by type
            for region in results['memory_regions']:
                region_type = region['type']
                if region_type not in memory_info['regions_by_type']:
                    memory_info['regions_by_type'][region_type] = 0
                memory_info['regions_by_type'][region_type] += 1
            
            return memory_info
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_process_tree(self) -> Dict:
        """
        Get process tree structure
        
        Returns:
            Dictionary representing process tree
        """
        tree = {}
        
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name']):
                try:
                    info = proc.info
                    pid = info['pid']
                    ppid = info['ppid']
                    
                    if ppid not in tree:
                        tree[ppid] = []
                    
                    tree[ppid].append({
                        'pid': pid,
                        'name': info['name']
                    })
                except:
                    pass
        except Exception as e:
            print(f"Error building process tree: {e}")
        
        return tree
    
    def get_all_processes(self) -> List[Dict]:
        """
        Get list of all current processes with basic info
        
        Returns:
            List of process dictionaries
        """
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'status', 'create_time']):
                try:
                    info = proc.info
                    info['create_time'] = datetime.fromtimestamp(info['create_time']).isoformat()
                    info['ppid'] = info.get('ppid', None)
                    
                    # Get exe path
                    try:
                        info['exe'] = proc.exe() if proc.exe() else "N/A"
                    except:
                        info['exe'] = "N/A"
                    
                    # Check if this process has been scanned
                    if info['pid'] in self.monitored_processes:
                        monitored = self.monitored_processes[info['pid']]
                        info['threat_detected'] = monitored.get('threat_detected', False)
                        info['yara_rule'] = monitored.get('yara_rule', None)
                        
                        scan_results = monitored.get('scan_results', {})
                        info['yara_matches'] = 1 if scan_results.get('matches_found') else 0
                    
                    processes.append(info)
                except:
                    pass
        except Exception as e:
            print(f"Error getting process list: {e}")
        
        return processes
    
    def kill_process(self, pid: int) -> bool:
        """
        Terminate a process
        
        Args:
            pid: Process ID to kill
            
        Returns:
            True if successful
        """
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            print(f"Process {pid} terminated successfully")
            return True
        except psutil.TimeoutExpired:
            # Force kill if terminate didn't work
            try:
                proc.kill()
                print(f"Process {pid} force killed")
                return True
            except:
                return False
        except Exception as e:
            print(f"Error killing process {pid}: {e}")
            return False
    
    def register_process_callback(self, callback: Callable):
        """
        Register a callback for new processes
        
        Args:
            callback: Function to call with process info
        """
        self.process_callbacks.append(callback)


# Example usage for testing
if __name__ == "__main__":
    monitor = ProcessMonitor(yara_rules_path=r"C:\Users\REM\Desktop\MAD\YDAMN")
    
    # Test getting current processes
    processes = monitor.get_all_processes()
    print(f"Found {len(processes)} running processes")
    
    # Test process info
    if processes:
        test_pid = processes[0]['pid']
        info = monitor.get_process_info(test_pid)
        if info:
            print(f"\nTest Process Info (PID {test_pid}):")
            print(f"  Name: {info['name']}")
            print(f"  EXE: {info['exe']}")
            print(f"  Parent: {info['parent_name']} (PID {info['parent_pid']})")
            
            # Test string extraction
            print(f"\nTesting string extraction...")
            strings = monitor.extract_strings_from_process(test_pid, min_length=4, limit=20)
            print(f"Extracted {len(strings)} strings (showing first 10):")
            for s in strings[:10]:
                print(f"  - {s}")
            
            # Test memory details if available
            if MEMORY_EXTRACTION_AVAILABLE:
                print(f"\nTesting memory details...")
                mem_info = monitor.get_process_memory_details(test_pid)
                if 'error' not in mem_info:
                    print(f"  Total regions: {mem_info['total_regions']}")
                    print(f"  Total bytes scanned: {mem_info['total_bytes']:,}")
                    print(f"  Regions by type: {mem_info['regions_by_type']}")
