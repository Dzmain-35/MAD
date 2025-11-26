"""
Sysmon Event Log Parser
Provides real-time monitoring of Sysmon events including Registry, File, Network, and Process activity

Sysmon Event IDs:
- 1: Process Create
- 3: Network Connection
- 7: Image Load (DLL)
- 8: CreateRemoteThread
- 10: Process Access
- 11: File Create
- 12: Registry Object Added or Deleted
- 13: Registry Value Set
- 14: Registry Object Renamed
- 15: File Create Stream Hash
- 17/18: Pipe Created/Connected
- 22: DNS Query

Requires Sysmon to be installed: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
"""

import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
from collections import deque
import queue
import platform


# Check if we're on Windows and can import win32evtlog
if platform.system() == "Windows":
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import win32event
        import pywintypes
        WINDOWS_EVTLOG_AVAILABLE = True
    except ImportError:
        WINDOWS_EVTLOG_AVAILABLE = False
        print("Warning: pywin32 not available. Sysmon parsing will be disabled.")
        print("Install with: pip install pywin32")
else:
    WINDOWS_EVTLOG_AVAILABLE = False


class SysmonEvent:
    """Represents a parsed Sysmon event"""

    # Event type mapping
    EVENT_TYPE_MAP = {
        1: "Process",
        3: "Network",
        7: "ImageLoad",
        8: "RemoteThread",
        10: "ProcessAccess",
        11: "File",
        12: "Registry",
        13: "Registry",
        14: "Registry",
        15: "File",
        17: "Pipe",
        18: "Pipe",
        22: "DNS"
    }

    # Operation mapping
    OPERATION_MAP = {
        1: "ProcessCreate",
        3: "NetworkConnect",
        7: "ImageLoad",
        8: "CreateRemoteThread",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "RegistryObjectAddedOrDeleted",
        13: "RegistryValueSet",
        14: "RegistryKeyRenamed",
        15: "FileCreateStreamHash",
        17: "PipeCreated",
        18: "PipeConnected",
        22: "DNSQuery"
    }

    def __init__(self, event_id: int, event_data: Dict[str, Any]):
        self.timestamp = event_data.get('TimeCreated', datetime.now())
        self.event_id = event_id
        self.event_type = self.EVENT_TYPE_MAP.get(event_id, "Unknown")
        self.operation = self.OPERATION_MAP.get(event_id, f"Event{event_id}")

        # Common fields
        self.pid = event_data.get('ProcessId', 0)
        self.tid = event_data.get('ThreadId', 0)
        self.process_name = event_data.get('Image', '')
        self.user = event_data.get('User', '')

        # Path/Target varies by event type
        self.path = self._extract_path(event_id, event_data)
        self.result = "SUCCESS"  # Sysmon only logs successful events
        self.detail = self._build_detail(event_id, event_data)

        # Store raw data for detailed analysis
        self.raw_data = event_data

    def _extract_path(self, event_id: int, data: Dict) -> str:
        """Extract the relevant path/target from event data"""
        if event_id in [11, 15]:  # File events
            return data.get('TargetFilename', '')
        elif event_id in [12, 13, 14]:  # Registry events
            return data.get('TargetObject', '')
        elif event_id == 3:  # Network
            dest_ip = data.get('DestinationIp', '')
            dest_port = data.get('DestinationPort', '')
            return f"{dest_ip}:{dest_port}" if dest_ip and dest_port else dest_ip
        elif event_id == 7:  # Image load
            return data.get('ImageLoaded', '')
        elif event_id == 22:  # DNS
            return data.get('QueryName', '')
        elif event_id == 1:  # Process create
            return data.get('CommandLine', data.get('Image', ''))
        else:
            return data.get('TargetObject', data.get('Image', ''))

    def _build_detail(self, event_id: int, data: Dict) -> str:
        """Build detailed description based on event type"""
        if event_id == 1:  # Process Create
            parent = data.get('ParentImage', 'Unknown')
            cmdline = data.get('CommandLine', '')
            return f"Parent: {parent} | Command: {cmdline[:100]}"
        elif event_id == 3:  # Network
            src = f"{data.get('SourceIp', '')}:{data.get('SourcePort', '')}"
            protocol = data.get('Protocol', '')
            return f"Source: {src} | Protocol: {protocol}"
        elif event_id in [12, 13, 14]:  # Registry
            event_type = data.get('EventType', '')
            return f"EventType: {event_type}"
        elif event_id == 11:  # File Create
            return f"File created: {data.get('TargetFilename', '')}"
        elif event_id == 7:  # Image Load
            signed = data.get('Signed', 'Unknown')
            signature = data.get('Signature', '')
            return f"Signed: {signed} | Signature: {signature}"
        elif event_id == 22:  # DNS
            query_results = data.get('QueryResults', '')
            return f"Results: {query_results}"
        else:
            return str(data)[:200]

    def to_dict(self) -> Dict:
        """Convert to dictionary for GUI display"""
        return {
            'timestamp': self.timestamp.strftime("%H:%M:%S.%f")[:-3] if isinstance(self.timestamp, datetime) else str(self.timestamp),
            'time_full': self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            'event_type': self.event_type,
            'operation': self.operation,
            'path': self.path,
            'result': self.result,
            'detail': self.detail,
            'pid': self.pid,
            'tid': self.tid,
            'process_name': self.process_name,
            'user': self.user,
            'event_id': self.event_id
        }

    def __str__(self):
        time_str = self.timestamp.strftime("%H:%M:%S.%f")[:-3] if isinstance(self.timestamp, datetime) else str(self.timestamp)
        return f"[{time_str}] {self.event_type:8s} | {self.operation:25s} | PID:{self.pid:5d} | {self.path}"


class SysmonLogMonitor:
    """
    Real-time Sysmon event log monitor
    Reads from Microsoft-Windows-Sysmon/Operational event log
    """

    SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, pid_filter: Optional[int] = None, max_events: int = 10000):
        """
        Initialize Sysmon log monitor

        Args:
            pid_filter: Only capture events for this PID (None for all processes)
            max_events: Maximum events to keep in buffer
        """
        self.pid_filter = pid_filter
        self.max_events = max_events

        # Event storage
        self.events = deque(maxlen=max_events)
        self.event_queue = queue.Queue()

        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None

        # Event callbacks
        self.event_callbacks = []

        # Statistics
        self.stats = {
            'total_events': 0,
            'file_events': 0,
            'registry_events': 0,
            'network_events': 0,
            'process_events': 0,
            'imageload_events': 0,
            'dns_events': 0
        }

        # Check if Sysmon is available
        self.sysmon_available = self._check_sysmon_available()

        # Track last read event record number to avoid duplicates
        self.last_record_number = 0

    def _check_sysmon_available(self) -> bool:
        """Check if Sysmon is installed and accessible"""
        if not WINDOWS_EVTLOG_AVAILABLE:
            return False

        try:
            # Try to open the Sysmon event log
            handle = win32evtlog.OpenEventLog(None, self.SYSMON_LOG_NAME)
            win32evtlog.CloseEventLog(handle)
            return True
        except Exception as e:
            print(f"Sysmon not available: {e}")
            return False

    def is_available(self) -> bool:
        """Check if Sysmon monitoring is available"""
        return self.sysmon_available

    def start_monitoring(self) -> bool:
        """Start monitoring Sysmon events"""
        if not self.sysmon_available:
            print("Sysmon is not installed or not accessible")
            return False

        if self.is_monitoring:
            return True

        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        return True

    def stop_monitoring(self):
        """Stop monitoring Sysmon events"""
        if not self.is_monitoring:
            return

        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)

    def _monitor_loop(self):
        """Main monitoring loop - reads Sysmon events in real-time"""
        try:
            # Open event log handle
            handle = win32evtlog.OpenEventLog(None, self.SYSMON_LOG_NAME)

            # Get the current newest record number
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if events:
                self.last_record_number = events[0].RecordNumber

            # Create event object for signaling
            signal_event = win32event.CreateEvent(None, 0, 0, None)
            win32evtlog.NotifyChangeEventLog(handle, signal_event)

            while self.is_monitoring:
                # Wait for new events (with timeout)
                result = win32event.WaitForSingleObject(signal_event, 1000)  # 1 second timeout

                if result == win32event.WAIT_OBJECT_0:
                    # New events available
                    self._read_new_events(handle)

                    # Re-register for next notification
                    win32evtlog.NotifyChangeEventLog(handle, signal_event)

                time.sleep(0.1)  # Small sleep to prevent CPU spinning

            # Cleanup
            win32evtlog.CloseEventLog(handle)
            win32event.CloseHandle(signal_event)

        except Exception as e:
            print(f"Error in Sysmon monitor loop: {e}")
            self.is_monitoring = False

    def _read_new_events(self, handle):
        """Read new events from the log"""
        try:
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)

            for event in events:
                # Skip if we've already processed this event
                if event.RecordNumber <= self.last_record_number:
                    continue

                # Parse the event
                parsed_event = self._parse_event(event)
                if parsed_event:
                    # Apply PID filter if set
                    if self.pid_filter is None or parsed_event.pid == self.pid_filter:
                        self._add_event(parsed_event)

                self.last_record_number = max(self.last_record_number, event.RecordNumber)

        except Exception as e:
            # Handle case where no events are available
            if not isinstance(e, pywintypes.error):
                print(f"Error reading events: {e}")

    def _parse_event(self, event) -> Optional[SysmonEvent]:
        """Parse a raw Windows event into a SysmonEvent"""
        try:
            event_id = event.EventID & 0xFFFF  # Mask off the severity bits

            # Only process Sysmon events we care about
            if event_id not in SysmonEvent.EVENT_TYPE_MAP:
                return None

            # Extract event data from the string data
            event_data = {}
            event_data['TimeCreated'] = event.TimeGenerated

            # Parse the event strings (Sysmon puts data in StringInserts)
            if event.StringInserts:
                # Different event types have different field orders
                # This is a simplified parser - real implementation would need
                # to handle each event type's specific format
                strings = event.StringInserts

                # Try to extract common fields
                for i, value in enumerate(strings):
                    if value and '=' in value:
                        # Handle "Key=Value" format
                        parts = value.split('=', 1)
                        if len(parts) == 2:
                            key, val = parts
                            event_data[key.strip()] = val.strip()

                # Fallback field extraction based on event type
                if event_id == 1 and len(strings) >= 5:  # Process Create
                    event_data.setdefault('Image', strings[4])
                    event_data.setdefault('CommandLine', strings[10] if len(strings) > 10 else '')
                    event_data.setdefault('ParentImage', strings[20] if len(strings) > 20 else '')
                elif event_id == 3 and len(strings) >= 5:  # Network
                    event_data.setdefault('Image', strings[4])
                    event_data.setdefault('DestinationIp', strings[14] if len(strings) > 14 else '')
                    event_data.setdefault('DestinationPort', strings[16] if len(strings) > 16 else '')
                elif event_id in [12, 13, 14]:  # Registry
                    event_data.setdefault('Image', strings[4] if len(strings) > 4 else '')
                    event_data.setdefault('TargetObject', strings[6] if len(strings) > 6 else '')
                elif event_id == 11:  # File Create
                    event_data.setdefault('Image', strings[4] if len(strings) > 4 else '')
                    event_data.setdefault('TargetFilename', strings[6] if len(strings) > 6 else '')

            # Extract PID from event (Windows event structure)
            # Note: This gets the PID from the event structure, not from Sysmon data
            event_data.setdefault('ProcessId', 0)

            return SysmonEvent(event_id, event_data)

        except Exception as e:
            print(f"Error parsing event: {e}")
            return None

    def _add_event(self, event: SysmonEvent):
        """Add event to storage and notify callbacks"""
        self.events.append(event)
        self.event_queue.put(event)

        # Update stats
        self.stats['total_events'] += 1
        if event.event_type == "File":
            self.stats['file_events'] += 1
        elif event.event_type == "Registry":
            self.stats['registry_events'] += 1
        elif event.event_type == "Network":
            self.stats['network_events'] += 1
        elif event.event_type == "Process":
            self.stats['process_events'] += 1
        elif event.event_type == "ImageLoad":
            self.stats['imageload_events'] += 1
        elif event.event_type == "DNS":
            self.stats['dns_events'] += 1

        # Notify callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"Error in event callback: {e}")

    def get_recent_events(self, count: int = 100, event_type: Optional[str] = None) -> List[Dict]:
        """
        Get recent events

        Args:
            count: Number of recent events to return
            event_type: Filter by event type or None for all

        Returns:
            List of event dictionaries
        """
        events = list(self.events)

        # Filter by type if specified
        if event_type:
            events = [e for e in events if e.event_type == event_type]

        # Return most recent
        return [e.to_dict() for e in list(events)[-count:]]

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
            'imageload_events': 0,
            'dns_events': 0
        }


# Example usage
if __name__ == "__main__":
    import sys

    print("=" * 80)
    print("Sysmon Event Monitor")
    print("=" * 80)
    print()

    # Check if Sysmon is available
    monitor = SysmonLogMonitor()
    if not monitor.is_available():
        print("ERROR: Sysmon is not installed or not accessible.")
        print("\nTo use this feature:")
        print("1. Download Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon")
        print("2. Install with default config: sysmon.exe -accepteula -i")
        print("3. Install pywin32: pip install pywin32")
        sys.exit(1)

    print("Sysmon is available!")
    print()

    # Get PID filter from command line
    pid_filter = None
    if len(sys.argv) > 1:
        pid_filter = int(sys.argv[1])
        print(f"Filtering events for PID: {pid_filter}")
    else:
        print("Monitoring all processes (no PID filter)")

    print()

    # Create monitor
    monitor = SysmonLogMonitor(pid_filter=pid_filter)

    # Register callback to print events
    def print_event(event):
        print(event)

    monitor.register_callback(print_event)

    # Start monitoring
    monitor.start_monitoring()

    print("Monitoring started. Press Ctrl+C to stop...")
    print()

    try:
        # Monitor indefinitely
        while True:
            time.sleep(1)

            # Print stats every 10 seconds
            if int(time.time()) % 10 == 0:
                stats = monitor.get_stats()
                print(f"\n--- Stats: {stats['total_events']} total events ---")

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
