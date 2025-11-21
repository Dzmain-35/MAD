"""
Process Monitor Module
Handles process monitoring, YARA scanning, and string extraction
"""

import psutil
import os
import threading
import time
import yara
import re
from datetime import datetime
from pathlib import Path


class ProcessMonitor:
    def __init__(self, yara_rules_path=None):
        """Initialize Process Monitor with YARA rules"""
        self.yara_rules_path = yara_rules_path
        self.yara_rules = None
        self.monitored_processes = {}
        self.monitoring_active = False
        self.monitoring_thread = None
        self.process_callbacks = []
        self.known_pids = set()

        # Load YARA rules
        if yara_rules_path:
            self.load_yara_rules()

    def load_yara_rules(self):
        """Load YARA rules from the specified directory"""
        try:
            if not os.path.exists(self.yara_rules_path):
                print(f"WARNING: YARA rules path does not exist: {self.yara_rules_path}")
                return

            yara_files = list(Path(self.yara_rules_path).glob("*.yara")) + \
                        list(Path(self.yara_rules_path).glob("*.yar"))

            if not yara_files:
                print(f"WARNING: No YARA rules found in {self.yara_rules_path}")
                return

            # Create rules dictionary
            rules_dict = {}
            for idx, yara_file in enumerate(yara_files):
                namespace = f"rule_{idx}_{yara_file.stem}"
                rules_dict[namespace] = str(yara_file)

            # Compile rules
            self.yara_rules = yara.compile(filepaths=rules_dict)
            print(f"Loaded {len(yara_files)} YARA rule files for process monitoring")

        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            self.yara_rules = None

    def register_process_callback(self, callback):
        """Register a callback for when new processes are detected"""
        self.process_callbacks.append(callback)

    def start_monitoring(self):
        """Start real-time process monitoring"""
        if self.monitoring_active:
            print("Process monitoring already active")
            return

        self.monitoring_active = True
        self.known_pids = {p.pid for p in psutil.process_iter(['pid'])}

        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        print("Process monitoring started")

    def stop_monitoring(self):
        """Stop real-time process monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)
        print("Process monitoring stopped")

    def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.monitoring_active:
            try:
                current_pids = {p.pid for p in psutil.process_iter(['pid'])}
                new_pids = current_pids - self.known_pids

                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        proc_info = {
                            'pid': pid,
                            'name': proc.name(),
                            'exe': proc.exe() if proc.exe() else 'N/A',
                            'threat_detected': False
                        }

                        # Scan new process with YARA
                        if self.yara_rules:
                            scan_result = self.scan_process(pid)
                            if scan_result.get('matches_found'):
                                proc_info['threat_detected'] = True
                                proc_info['yara_rule'] = scan_result.get('rule', 'Unknown')
                                proc_info['scan_results'] = scan_result

                                # Notify callbacks
                                for callback in self.process_callbacks:
                                    try:
                                        callback(proc_info)
                                    except Exception as e:
                                        print(f"Error in process callback: {e}")

                        self.monitored_processes[pid] = proc_info

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                self.known_pids = current_pids
                time.sleep(2)  # Check every 2 seconds

            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(5)

    def get_all_processes(self):
        """Get list of all current processes"""
        processes = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
            try:
                info = proc.info
                proc_data = {
                    'pid': info['pid'],
                    'name': info['name'],
                    'exe': info.get('exe', 'N/A') or 'N/A',
                    'ppid': info.get('ppid', 0),
                    'threat_detected': False,
                    'yara_rule': None,
                    'yara_matches': 0
                }

                # Check if already monitored
                if info['pid'] in self.monitored_processes:
                    monitored = self.monitored_processes[info['pid']]
                    proc_data['threat_detected'] = monitored.get('threat_detected', False)
                    proc_data['yara_rule'] = monitored.get('yara_rule')
                    if 'scan_results' in monitored:
                        proc_data['yara_matches'] = monitored['scan_results'].get('matches_found', 0)

                processes.append(proc_data)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def scan_process(self, pid):
        """Scan a process with YARA rules"""
        try:
            proc = psutil.Process(pid)

            if not self.yara_rules:
                return {
                    'error': 'No YARA rules loaded',
                    'matches_found': False
                }

            # Try to scan process memory
            try:
                # Get process executable path
                exe_path = proc.exe()

                if not exe_path or not os.path.exists(exe_path):
                    return {
                        'error': 'Cannot access process executable',
                        'matches_found': False
                    }

                # Scan the executable file
                matches = self.yara_rules.match(exe_path)

                if matches:
                    # Extract matched strings
                    matched_strings = []
                    rule_name = matches[0].rule

                    for match in matches:
                        for string_match in match.strings:
                            matched_strings.append(string_match[2].decode('utf-8', errors='ignore'))

                    # Calculate threat score
                    threat_score = min(len(matches) * 30 + 40, 100)

                    return {
                        'matches_found': True,
                        'rule': rule_name,
                        'threat_score': threat_score,
                        'risk_level': 'Critical' if threat_score >= 70 else 'High',
                        'strings': matched_strings[:20]  # Limit to 20 strings
                    }
                else:
                    return {
                        'matches_found': False,
                        'rule': 'No_YARA_Hit',
                        'threat_score': 0,
                        'risk_level': 'Low',
                        'strings': []
                    }

            except Exception as e:
                return {
                    'error': f'Scan error: {str(e)}',
                    'matches_found': False
                }

        except psutil.NoSuchProcess:
            return {'error': 'Process not found', 'matches_found': False}
        except psutil.AccessDenied:
            return {'error': 'Access denied', 'matches_found': False}
        except Exception as e:
            return {'error': str(e), 'matches_found': False}

    def get_process_info(self, pid):
        """Get detailed information about a process"""
        try:
            proc = psutil.Process(pid)

            info = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe() if proc.exe() else 'N/A',
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else 'N/A',
                'status': proc.status(),
                'username': proc.username() if proc.username() else 'N/A',
                'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'parent_pid': proc.ppid() if proc.ppid() else 0,
                'parent_name': 'N/A'
            }

            # Get parent process name
            try:
                parent = psutil.Process(info['parent_pid'])
                info['parent_name'] = parent.name()
            except:
                pass

            # Get resource usage
            try:
                info['cpu_percent'] = proc.cpu_percent(interval=0.1)
                info['memory_info'] = {'rss': proc.memory_info().rss}
                info['num_threads'] = proc.num_threads()
            except:
                pass

            # Get network connections
            try:
                connections = []
                for conn in proc.connections():
                    connections.append({
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                        'status': conn.status
                    })
                info['connections'] = connections
            except:
                info['connections'] = []

            return info

        except psutil.NoSuchProcess:
            return None
        except Exception as e:
            print(f"Error getting process info: {e}")
            return None

    def extract_strings_from_process(self, pid, min_length=4, limit=1000):
        """
        Extract strings from a process memory/executable
        FIXED: Extract MORE strings from process
        """
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()

            if not exe_path or not os.path.exists(exe_path):
                return []

            # Read executable file and extract strings
            strings = []

            with open(exe_path, 'rb') as f:
                # Read file in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                data = f.read(chunk_size * 10)  # Read first 10MB max

                # Extract ASCII strings (enhanced pattern for more strings)
                # FIXED: More comprehensive regex to catch more strings
                ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
                for match in re.finditer(ascii_pattern, data):
                    s = match.group().decode('ascii', errors='ignore')
                    if len(s) >= min_length:
                        strings.append(s)
                        if len(strings) >= limit * 2:  # FIXED: Extract 2x more strings
                            break

                # Extract Unicode strings (UTF-16 LE)
                f.seek(0)
                data = f.read(chunk_size * 10)
                unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
                for match in re.finditer(unicode_pattern, data):
                    try:
                        s = match.group().decode('utf-16le', errors='ignore')
                        if len(s) >= min_length:
                            strings.append(s)
                            if len(strings) >= limit * 2:  # FIXED: Extract 2x more strings
                                break
                    except:
                        pass

            # Remove duplicates while preserving order
            seen = set()
            unique_strings = []
            for s in strings:
                if s not in seen and len(s.strip()) > 0:
                    seen.add(s)
                    unique_strings.append(s.strip())

            # FIXED: Return up to limit*2 strings (was limit before)
            return unique_strings[:limit * 2]

        except Exception as e:
            print(f"Error extracting strings: {e}")
            return []

    def kill_process(self, pid):
        """Terminate a process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            # Wait up to 3 seconds for termination
            proc.wait(timeout=3)
            return True
        except psutil.TimeoutExpired:
            # Force kill if terminate didn't work
            try:
                proc.kill()
                return True
            except:
                return False
        except Exception as e:
            print(f"Error killing process: {e}")
            return False
