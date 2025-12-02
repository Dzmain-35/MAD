"""
System-Wide Activity Monitor
Monitors all system activity (all processes) for file, registry, network, and process events

This provides a "bird's eye view" of system activity, useful for:
- Initial triage and threat hunting
- Detecting suspicious process chains
- Identifying lateral movement
- Catching new malicious processes

Combines multiple data sources:
1. Sysmon events (if available) - Best quality, includes Registry
2. psutil polling - Fallback for basic monitoring
"""

import threading
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any, Set
from collections import deque
import queue

try:
    import psutil
except ImportError:
    print("Error: psutil not available")
    psutil = None

# Import our monitoring modules
from .sysmon_parser import SysmonLogMonitor, SysmonEvent
from .procmon_events import ProcmonEvent


class EventFilter:
    """Advanced event filtering with regex, time range, and suspicious pattern matching"""

    def __init__(self):
        self.event_types: Optional[List[str]] = None  # None = all types
        self.pid_filter: Optional[int] = None
        self.pid_filter_set: Optional[set] = None  # For filtering by multiple PIDs (parent + children)
        self.path_regex: Optional[str] = None
        self.path_pattern = None
        self.time_start: Optional[datetime] = None
        self.time_end: Optional[datetime] = None
        self.suspicious_only: bool = False
        self.operation_filter: Optional[List[str]] = None

        # Suspicious patterns
        self.suspicious_patterns = {
            'file': [
                r'.*\\AppData\\Roaming\\.*\.exe$',  # Executable in AppData
                r'.*\\Temp\\.*\.exe$',  # Executable in Temp
                r'.*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.*',  # Startup folder
                r'.*\.scr$',  # Screensaver files
                r'.*\.hta$',  # HTML applications
                r'.*\.vbs$',  # VBScript
                r'.*\.ps1$',  # PowerShell scripts
            ],
            'registry': [
                r'.*\\Run\\.*',  # Run keys
                r'.*\\RunOnce\\.*',  # RunOnce keys
                r'.*\\RunServices\\.*',  # RunServices
                r'.*\\Winlogon\\.*',  # Winlogon keys
                r'.*\\Image File Execution Options\\.*',  # IFEO for persistence
                r'.*\\AppInit_DLLs.*',  # AppInit DLLs
                r'.*\\BootExecute.*',  # Boot execute
                r'.*\\Userinit.*',  # Userinit
                r'.*\\Shell\\.*',  # Shell modifications
            ],
            'process': [
                r'.*powershell\.exe.*-enc.*',  # Encoded PowerShell
                r'.*powershell\.exe.*-e .*',  # Encoded PowerShell (short form)
                r'.*powershell\.exe.*downloadstring.*',  # Download cradle
                r'.*cmd\.exe.*/c.*',  # cmd.exe with /c
                r'.*rundll32\.exe.*',  # rundll32 (often used for malware)
                r'.*regsvr32\.exe.*',  # regsvr32 (squiblydoo)
                r'.*mshta\.exe.*',  # mshta (HTML application host)
                r'.*wscript\.exe.*',  # Windows Script Host
                r'.*cscript\.exe.*',  # Windows Script Host
            ],
            'network': [
                r'.*:(4444|5555|6666|7777|8888|31337)$',  # Common backdoor ports
                r'.*:443$',  # HTTPS (check if from suspicious process)
            ]
        }

    def set_event_types(self, types: Optional[List[str]]):
        """Set event type filter"""
        self.event_types = types

    def set_pid(self, pid: Optional[int]):
        """Set PID filter"""
        self.pid_filter = pid
        # Clear pid_filter_set when setting single PID
        if pid is None:
            self.pid_filter_set = None

    def set_pid_set(self, pids: Optional[set]):
        """Set PID filter with multiple PIDs (for child process filtering)"""
        self.pid_filter_set = pids
        # If using pid set, clear single PID filter
        if pids:
            self.pid_filter = None

    def set_path_regex(self, regex: Optional[str]):
        """Set path regex filter"""
        self.path_regex = regex
        if regex:
            try:
                self.path_pattern = re.compile(regex, re.IGNORECASE)
            except re.error:
                self.path_pattern = None

    def set_time_range(self, start: Optional[datetime], end: Optional[datetime]):
        """Set time range filter"""
        self.time_start = start
        self.time_end = end

    def set_suspicious_only(self, enabled: bool):
        """Enable/disable suspicious-only filtering"""
        self.suspicious_only = enabled

    def set_operations(self, operations: Optional[List[str]]):
        """Set operation filter"""
        self.operation_filter = operations

    def matches(self, event: Dict) -> bool:
        """Check if event matches all filter criteria"""

        # Event type filter
        if self.event_types and event.get('event_type') not in self.event_types:
            return False

        # PID filter (single PID or set of PIDs)
        if self.pid_filter_set is not None:
            if event.get('pid') not in self.pid_filter_set:
                return False
        elif self.pid_filter is not None:
            if event.get('pid') != self.pid_filter:
                return False

        # Path regex filter
        if self.path_pattern and event.get('path'):
            if not self.path_pattern.search(str(event.get('path', ''))):
                return False

        # Time range filter
        event_time = event.get('timestamp')
        if isinstance(event_time, str):
            try:
                # Parse time string
                event_time = datetime.fromisoformat(event.get('time_full', event_time))
            except:
                pass

        if isinstance(event_time, datetime):
            if self.time_start and event_time < self.time_start:
                return False
            if self.time_end and event_time > self.time_end:
                return False

        # Operation filter
        if self.operation_filter and event.get('operation') not in self.operation_filter:
            return False

        # Suspicious-only filter
        if self.suspicious_only and not self.is_suspicious(event):
            return False

        return True

    def is_suspicious(self, event: Dict) -> bool:
        """Check if event matches suspicious patterns"""
        event_type = event.get('event_type', '').lower()
        path = str(event.get('path', '')).lower()
        operation = str(event.get('operation', '')).lower()
        detail = str(event.get('detail', '')).lower()

        # Check against suspicious patterns
        patterns = self.suspicious_patterns.get(event_type, [])
        for pattern in patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
            if re.search(pattern, detail, re.IGNORECASE):
                return True

        # Additional heuristics
        if event_type == 'process':
            # Check for suspicious process names
            suspicious_procs = ['powershell', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript']
            if any(proc in path.lower() for proc in suspicious_procs):
                # Check for suspicious command line patterns
                if any(term in detail.lower() for term in ['encoded', 'downloadstring', 'invoke-expression', 'iex', 'bypass']):
                    return True

        elif event_type == 'network':
            # Check for suspicious ports
            suspicious_ports = ['4444', '5555', '6666', '7777', '8888', '31337']
            if any(port in path for port in suspicious_ports):
                return True

        elif event_type == 'file':
            # Check for double extensions
            if path.count('.') > 1 and any(ext in path for ext in ['.exe', '.scr', '.bat', '.vbs', '.ps1']):
                return True

        return False


class SystemWideMonitor:
    """
    System-wide activity monitor
    Monitors all processes for file, registry, network, and process activity
    """

    def __init__(self, max_events: int = 50000):
        """
        Initialize system-wide monitor

        Args:
            max_events: Maximum events to keep in buffer (larger for system-wide)
        """
        self.max_events = max_events

        # Event storage
        self.events = deque(maxlen=max_events)
        self.event_queue = queue.Queue()

        # Monitoring state
        self.is_monitoring = False
        self.monitor_threads = []

        # Event callbacks
        self.event_callbacks = []

        # Statistics
        self.stats = {
            'total_events': 0,
            'file_events': 0,
            'registry_events': 0,
            'network_events': 0,
            'process_events': 0,
            'thread_events': 0,
            'imageload_events': 0,
            'dns_events': 0
        }

        # Sysmon monitor (if available)
        self.sysmon_monitor = None
        self.sysmon_available = False
        try:
            self.sysmon_monitor = SysmonLogMonitor(pid_filter=None, max_events=max_events)
            self.sysmon_available = self.sysmon_monitor.is_available()
            if self.sysmon_available:
                print("System-wide monitor: Sysmon available, will use for enhanced monitoring")
        except Exception as e:
            print(f"System-wide monitor: Sysmon not available: {e}")

        # Fallback: Process monitoring with psutil
        self.known_processes: Set[int] = set()
        self.known_connections: Dict[int, Set] = {}  # pid -> set of connections

        # Event filter
        self.event_filter = EventFilter()

        # Last event timestamp for incremental updates
        self.last_update_time = datetime.now()

    def start_monitoring(self) -> bool:
        """Start system-wide monitoring"""
        if self.is_monitoring:
            return True

        self.is_monitoring = True

        # Start Sysmon monitor if available
        if self.sysmon_available and self.sysmon_monitor:
            self.sysmon_monitor.register_callback(self._on_sysmon_event)
            self.sysmon_monitor.start_monitoring()
            print("System-wide monitor: Sysmon monitoring started")

        # ALWAYS start psutil fallback for process/network monitoring
        # This ensures we have events even if Sysmon fails or is slow
        print("System-wide monitor: Starting psutil process/network monitoring")
        self.monitor_threads = [
            threading.Thread(target=self._monitor_processes, daemon=True),
            threading.Thread(target=self._monitor_network, daemon=True),
        ]

        for thread in self.monitor_threads:
            thread.start()

        return True

    def stop_monitoring(self):
        """Stop system-wide monitoring"""
        if not self.is_monitoring:
            return

        self.is_monitoring = False

        # Stop Sysmon monitor
        if self.sysmon_monitor:
            self.sysmon_monitor.stop_monitoring()

        # Wait for threads to finish
        for thread in self.monitor_threads:
            if thread.is_alive():
                thread.join(timeout=2)

    def _on_sysmon_event(self, sysmon_event: SysmonEvent):
        """Callback for Sysmon events"""
        # Convert Sysmon event to our standard format and add
        event_dict = sysmon_event.to_dict()

        # Apply filter
        if self.event_filter.matches(event_dict):
            self._add_event(event_dict)
        else:
            # Debug: event was filtered out
            pass

    def _add_event(self, event: Dict):
        """Add event to storage and notify callbacks"""
        self.events.append(event)
        self.event_queue.put(event)

        # Update stats
        self.stats['total_events'] += 1
        event_type = event.get('event_type', '').lower()
        if 'file' in event_type:
            self.stats['file_events'] += 1
        elif 'registry' in event_type:
            self.stats['registry_events'] += 1
        elif 'network' in event_type or 'dns' in event_type:
            self.stats['network_events'] += 1
            if 'dns' in event_type:
                self.stats['dns_events'] += 1
        elif 'process' in event_type:
            self.stats['process_events'] += 1
        elif 'thread' in event_type:
            self.stats['thread_events'] += 1
        elif 'imageload' in event_type:
            self.stats['imageload_events'] += 1

        # Debug output for first 10 events
        if self.stats['total_events'] <= 10:
            print(f"[DEBUG] Event #{self.stats['total_events']}: {event_type} | {event.get('operation')} | PID:{event.get('pid')} | {event.get('path', '')[:50]}")

        # Notify callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"Error in event callback: {e}")

    def _monitor_processes(self):
        """Monitor process creation/termination (psutil fallback)"""
        # Initialize known processes
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                self.known_processes.add(proc.info['pid'])
        except:
            pass

        while self.is_monitoring:
            try:
                current_processes = set()

                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    pid = proc.info['pid']
                    current_processes.add(pid)

                    # New process detected
                    if pid not in self.known_processes:
                        try:
                            cmdline = ' '.join(proc.info.get('cmdline', [])) if proc.info.get('cmdline') else ''
                            exe = proc.info.get('exe', proc.info.get('name', 'Unknown'))

                            event = {
                                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                'time_full': datetime.now().isoformat(),
                                'event_type': 'Process',
                                'operation': 'ProcessCreate',
                                'path': exe,
                                'result': 'SUCCESS',
                                'detail': f'Command: {cmdline[:150]}',
                                'pid': pid,
                                'tid': 0,
                                'process_name': proc.info.get('name', 'Unknown')
                            }

                            if self.event_filter.matches(event):
                                self._add_event(event)

                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                # Detect terminated processes
                terminated = self.known_processes - current_processes
                for pid in terminated:
                    event = {
                        'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        'time_full': datetime.now().isoformat(),
                        'event_type': 'Process',
                        'operation': 'ProcessTerminate',
                        'path': f'PID {pid}',
                        'result': 'SUCCESS',
                        'detail': 'Process terminated',
                        'pid': pid,
                        'tid': 0,
                        'process_name': ''
                    }

                    if self.event_filter.matches(event):
                        self._add_event(event)

                self.known_processes = current_processes

                time.sleep(1)  # Check every second

            except Exception as e:
                print(f"Error monitoring processes: {e}")
                time.sleep(2)

    def _monitor_network(self):
        """Monitor network connections (psutil fallback)"""
        while self.is_monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pid = proc.info['pid']
                        proc_obj = psutil.Process(pid)
                        connections = proc_obj.connections()

                        current_conns = set()
                        for conn in connections:
                            if conn.raddr:  # Has remote address
                                conn_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                                current_conns.add(conn_id)

                                # Check if this is a new connection
                                if pid not in self.known_connections:
                                    self.known_connections[pid] = set()

                                if conn_id not in self.known_connections[pid]:
                                    event = {
                                        'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                        'time_full': datetime.now().isoformat(),
                                        'event_type': 'Network',
                                        'operation': 'NetworkConnect',
                                        'path': f"{conn.raddr.ip}:{conn.raddr.port}",
                                        'result': conn.status,
                                        'detail': f"Local: {conn.laddr.ip}:{conn.laddr.port} | Protocol: {conn.type}",
                                        'pid': pid,
                                        'tid': 0,
                                        'process_name': proc.info.get('name', 'Unknown')
                                    }

                                    if self.event_filter.matches(event):
                                        self._add_event(event)

                        self.known_connections[pid] = current_conns

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                time.sleep(2)  # Check every 2 seconds

            except Exception as e:
                print(f"Error monitoring network: {e}")
                time.sleep(3)

    def get_recent_events(self, count: int = 1000, event_type: Optional[str] = None,
                          since: Optional[datetime] = None) -> List[Dict]:
        """
        Get recent events with optional filtering

        Args:
            count: Number of recent events to return
            event_type: Filter by event type or None for all
            since: Only return events after this time (for incremental updates)

        Returns:
            List of event dictionaries
        """
        events = list(self.events)

        # Filter by time if specified
        if since:
            events = [e for e in events if self._parse_event_time(e) > since]

        # Filter by type if specified
        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]

        # Return most recent
        return list(events)[-count:]

    def _parse_event_time(self, event: Dict) -> datetime:
        """Parse event timestamp to datetime"""
        time_full = event.get('time_full')
        if time_full:
            try:
                return datetime.fromisoformat(time_full)
            except:
                pass
        return datetime.min

    def get_events_since(self, since: datetime) -> List[Dict]:
        """Get all events since a specific time (for incremental updates)"""
        return self.get_recent_events(count=len(self.events), since=since)

    def get_stats(self) -> Dict:
        """Get event statistics"""
        return self.stats.copy()

    def register_callback(self, callback: Callable):
        """Register a callback for new events"""
        self.event_callbacks.append(callback)

    def clear_events(self):
        """Clear all stored events"""
        self.events.clear()
        self.stats = {
            'total_events': 0,
            'file_events': 0,
            'registry_events': 0,
            'network_events': 0,
            'process_events': 0,
            'thread_events': 0,
            'imageload_events': 0,
            'dns_events': 0
        }

    def set_filter(self, event_filter: EventFilter):
        """Set the event filter"""
        self.event_filter = event_filter

    def get_filter(self) -> EventFilter:
        """Get the current event filter"""
        return self.event_filter


# Example usage
if __name__ == "__main__":
    import sys

    print("=" * 80)
    print("System-Wide Activity Monitor")
    print("=" * 80)
    print()

    # Create monitor
    monitor = SystemWideMonitor(max_events=10000)

    # Set up filter if requested
    if "--suspicious" in sys.argv:
        print("Filtering for suspicious events only...")
        monitor.get_filter().set_suspicious_only(True)

    # Register callback to print events
    def print_event(event):
        print(f"[{event['timestamp']}] {event['event_type']:10s} | PID:{event['pid']:5d} | "
              f"{event['operation']:20s} | {event['path'][:60]}")

    monitor.register_callback(print_event)

    # Start monitoring
    print("Starting system-wide monitoring...")
    monitor.start_monitoring()
    print("Monitoring started. Press Ctrl+C to stop...")
    print()

    try:
        # Monitor indefinitely
        while True:
            time.sleep(5)

            # Print stats every 5 seconds
            stats = monitor.get_stats()
            print(f"\n--- Stats: {stats['total_events']} total events | "
                  f"File: {stats['file_events']} | Registry: {stats['registry_events']} | "
                  f"Network: {stats['network_events']} | Process: {stats['process_events']} ---")

    except KeyboardInterrupt:
        print("\n\nStopping monitor...")

    # Stop monitoring
    monitor.stop_monitoring()

    # Print final stats
    print()
    print("=" * 80)
    print("Final Statistics:")
    print("=" * 80)
    stats = monitor.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
