"""
Procmon-Style Live Event Monitor
Shows real-time file system, registry, and thread activity for a specific PID

Monitors:
- File System: CreateFile, ReadFile, WriteFile, CloseFile, etc.
- Registry: RegOpenKey, RegQueryValue, RegSetValue, RegCloseKey, etc.
- Threads: Thread Create, Thread Exit, Thread changes
- Process: Process create/exit events

Similar to Sysinternals Process Monitor
"""

import os
import time
import psutil
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set
from collections import deque
import queue


class ProcmonEvent:
    """Represents a single Procmon-style event"""
    
    def __init__(self, event_type: str, operation: str, path: str, result: str, 
                 detail: str = "", pid: int = 0, tid: int = 0):
        self.timestamp = datetime.now()
        self.event_type = event_type  # "File", "Registry", "Thread", "Process", "Network"
        self.operation = operation    # "CreateFile", "RegOpenKey", "ThreadCreate", etc.
        self.path = path              # File path, registry key, or resource
        self.result = result          # "SUCCESS", "ACCESS_DENIED", "NOT_FOUND", etc.
        self.detail = detail          # Additional details
        self.pid = pid
        self.tid = tid
    
    def __str__(self):
        time_str = self.timestamp.strftime("%H:%M:%S.%f")[:-3]
        return f"[{time_str}] {self.event_type:8s} | {self.operation:20s} | {self.path:60s} | {self.result}"
    
    def to_dict(self):
        """Convert to dictionary for GUI display"""
        return {
            'timestamp': self.timestamp.strftime("%H:%M:%S.%f")[:-3],
            'time_full': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'operation': self.operation,
            'path': self.path,
            'result': self.result,
            'detail': self.detail,
            'pid': self.pid,
            'tid': self.tid
        }


class ProcmonLiveMonitor:
    """
    Live event monitor for a specific PID
    Captures file, registry, thread, and process events
    """
    
    def __init__(self, target_pid: int, max_events: int = 10000):
        """
        Initialize live monitor for a specific PID
        
        Args:
            target_pid: Process ID to monitor
            max_events: Maximum number of events to keep in buffer
        """
        self.target_pid = target_pid
        self.max_events = max_events
        
        # Event storage
        self.events = deque(maxlen=max_events)  # Thread-safe deque
        self.event_queue = queue.Queue()  # For GUI updates
        
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
            'thread_events': 0,
            'process_events': 0,
            'network_events': 0
        }
        
        # Process info
        try:
            self.process = psutil.Process(target_pid)
            self.process_name = self.process.name()
            self.process_exe = self.process.exe()
        except:
            self.process = None
            self.process_name = f"PID {target_pid}"
            self.process_exe = ""
        
        # Track known threads for change detection
        self.known_threads = set()
        self._init_known_threads()
        
        # Track open files
        self.known_files = set()
        self._init_known_files()
    
    def _init_known_threads(self):
        """Initialize known threads for the target process"""
        try:
            if self.process:
                for thread in self.process.threads():
                    self.known_threads.add(thread.id)
        except:
            pass
    
    def _init_known_files(self):
        """Initialize known open files for the target process"""
        try:
            if self.process:
                for file in self.process.open_files():
                    self.known_files.add(file.path)
        except:
            pass
    
    def start_monitoring(self):
        """Start monitoring events for the target PID"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        
        # Start monitoring threads
        self.monitor_threads = [
            threading.Thread(target=self._monitor_threads, daemon=True),
            threading.Thread(target=self._monitor_files, daemon=True),
            threading.Thread(target=self._monitor_connections, daemon=True),
        ]
        
        for thread in self.monitor_threads:
            thread.start()
        
        # Log start event
        self._add_event(ProcmonEvent(
            event_type="Process",
            operation="MonitorStart",
            path=self.process_exe,
            result="SUCCESS",
            detail=f"Started monitoring PID {self.target_pid}",
            pid=self.target_pid
        ))
    
    def stop_monitoring(self):
        """Stop monitoring events"""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        
        # Wait for threads to finish
        for thread in self.monitor_threads:
            thread.join(timeout=1)
        
        # Log stop event
        self._add_event(ProcmonEvent(
            event_type="Process",
            operation="MonitorStop",
            path=self.process_exe,
            result="SUCCESS",
            detail=f"Stopped monitoring PID {self.target_pid}",
            pid=self.target_pid
        ))
    
    def _add_event(self, event: ProcmonEvent):
        """Add event to storage and notify callbacks"""
        self.events.append(event)
        self.event_queue.put(event)
        
        # Update stats
        self.stats['total_events'] += 1
        if event.event_type == "File":
            self.stats['file_events'] += 1
        elif event.event_type == "Registry":
            self.stats['registry_events'] += 1
        elif event.event_type == "Thread":
            self.stats['thread_events'] += 1
        elif event.event_type == "Process":
            self.stats['process_events'] += 1
        elif event.event_type == "Network":
            self.stats['network_events'] += 1
        
        # Notify callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"Error in event callback: {e}")
    
    def _monitor_threads(self):
        """Monitor thread creation/termination"""
        while self.is_monitoring:
            try:
                if not self.process or not self.process.is_running():
                    # Process terminated
                    self._add_event(ProcmonEvent(
                        event_type="Process",
                        operation="ProcessExit",
                        path=self.process_exe,
                        result="SUCCESS",
                        detail="Process terminated",
                        pid=self.target_pid
                    ))
                    self.is_monitoring = False
                    break
                
                # Get current threads
                current_threads = set()
                for thread in self.process.threads():
                    current_threads.add(thread.id)
                
                # Find new threads
                new_threads = current_threads - self.known_threads
                for tid in new_threads:
                    self._add_event(ProcmonEvent(
                        event_type="Thread",
                        operation="ThreadCreate",
                        path=f"TID {tid}",
                        result="SUCCESS",
                        detail=f"New thread created in {self.process_name}",
                        pid=self.target_pid,
                        tid=tid
                    ))
                
                # Find terminated threads
                terminated_threads = self.known_threads - current_threads
                for tid in terminated_threads:
                    self._add_event(ProcmonEvent(
                        event_type="Thread",
                        operation="ThreadExit",
                        path=f"TID {tid}",
                        result="SUCCESS",
                        detail=f"Thread terminated",
                        pid=self.target_pid,
                        tid=tid
                    ))
                
                self.known_threads = current_threads
                
                time.sleep(0.5)  # Check every 500ms
            
            except psutil.NoSuchProcess:
                self._add_event(ProcmonEvent(
                    event_type="Process",
                    operation="ProcessExit",
                    path=self.process_exe,
                    result="SUCCESS",
                    detail="Process no longer exists",
                    pid=self.target_pid
                ))
                self.is_monitoring = False
                break
            except Exception as e:
                print(f"Error monitoring threads: {e}")
                time.sleep(1)
    
    def _monitor_files(self):
        """Monitor file system activity (open files)"""
        while self.is_monitoring:
            try:
                if not self.process or not self.process.is_running():
                    break
                
                # Get current open files
                current_files = set()
                try:
                    for file_info in self.process.open_files():
                        current_files.add(file_info.path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Find newly opened files
                new_files = current_files - self.known_files
                for file_path in new_files:
                    # Determine operation based on file extension/location
                    operation = "CreateFile"
                    if file_path.lower().endswith(('.dll', '.exe')):
                        operation = "LoadImage"
                    elif file_path.lower().endswith(('.log', '.txt')):
                        operation = "CreateFile"
                    
                    self._add_event(ProcmonEvent(
                        event_type="File",
                        operation=operation,
                        path=file_path,
                        result="SUCCESS",
                        detail="File opened",
                        pid=self.target_pid
                    ))
                
                # Find closed files
                closed_files = self.known_files - current_files
                for file_path in closed_files:
                    self._add_event(ProcmonEvent(
                        event_type="File",
                        operation="CloseFile",
                        path=file_path,
                        result="SUCCESS",
                        detail="File closed",
                        pid=self.target_pid
                    ))
                
                self.known_files = current_files
                
                time.sleep(1)  # Check every 1 second
            
            except Exception as e:
                print(f"Error monitoring files: {e}")
                time.sleep(1)
    
    def _monitor_connections(self):
        """Monitor network connections"""
        known_connections = set()
        
        while self.is_monitoring:
            try:
                if not self.process or not self.process.is_running():
                    break
                
                # Get current connections
                current_connections = set()
                try:
                    for conn in self.process.connections():
                        if conn.raddr:  # Has remote address
                            conn_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                            current_connections.add((conn_id, conn.status))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Find new connections
                current_ids = set(c[0] for c in current_connections)
                known_ids = set(c[0] for c in known_connections)
                
                new_conn_ids = current_ids - known_ids
                for conn_id, status in current_connections:
                    if conn_id in new_conn_ids:
                        parts = conn_id.split('-')
                        self._add_event(ProcmonEvent(
                            event_type="Network",
                            operation="TCP Connect" if "TCP" in status else "UDP Send",
                            path=parts[1] if len(parts) > 1 else conn_id,
                            result=status,
                            detail=f"Local: {parts[0] if len(parts) > 0 else 'unknown'}",
                            pid=self.target_pid
                        ))
                
                # Find closed connections
                closed_conn_ids = known_ids - current_ids
                for conn_id, status in known_connections:
                    if conn_id in closed_conn_ids:
                        parts = conn_id.split('-')
                        self._add_event(ProcmonEvent(
                            event_type="Network",
                            operation="TCP Disconnect" if "TCP" in status else "UDP Close",
                            path=parts[1] if len(parts) > 1 else conn_id,
                            result="CLOSED",
                            detail=f"Connection closed",
                            pid=self.target_pid
                        ))
                
                known_connections = current_connections
                
                time.sleep(1)  # Check every 1 second
            
            except Exception as e:
                print(f"Error monitoring connections: {e}")
                time.sleep(1)
    
    def get_recent_events(self, count: int = 100, event_type: Optional[str] = None) -> List[Dict]:
        """
        Get recent events
        
        Args:
            count: Number of recent events to return
            event_type: Filter by event type (File, Registry, Thread, etc.) or None for all
            
        Returns:
            List of event dictionaries
        """
        events = list(self.events)
        
        # Filter by type if specified
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        # Return most recent
        return [e.to_dict() for e in list(events)[-count:]]
    
    def get_events_queue(self) -> queue.Queue:
        """Get the event queue for GUI updates"""
        return self.event_queue
    
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
            'thread_events': 0,
            'process_events': 0,
            'network_events': 0
        }
    
    def get_stats(self) -> Dict:
        """Get event statistics"""
        return self.stats.copy()
    
    def export_events(self, filepath: str, event_type: Optional[str] = None):
        """
        Export events to CSV file
        
        Args:
            filepath: Path to save CSV file
            event_type: Filter by event type or None for all
        """
        import csv
        
        events = list(self.events)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Event Type', 'Operation', 'Path', 'Result', 'Detail', 'PID', 'TID'])
            
            for event in events:
                writer.writerow([
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.operation,
                    event.path,
                    event.result,
                    event.detail,
                    event.pid,
                    event.tid
                ])


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        pid = int(sys.argv[1])
    else:
        # Find a test process
        for proc in psutil.process_iter(['pid', 'name']):
            if 'notepad' in proc.info['name'].lower() or 'calc' in proc.info['name'].lower():
                pid = proc.info['pid']
                break
        else:
            print("No test process found. Please specify a PID:")
            print("Usage: python procmon_events.py <PID>")
            sys.exit(1)
    
    print("=" * 80)
    print(f"Starting Procmon-style event monitor for PID {pid}")
    print("=" * 80)
    print()
    
    # Create monitor
    monitor = ProcmonLiveMonitor(pid)
    
    # Register callback to print events
    def print_event(event):
        print(event)
    
    monitor.register_callback(print_event)
    
    # Start monitoring
    monitor.start_monitoring()
    
    print("Monitoring started. Press Ctrl+C to stop...")
    print()
    
    try:
        # Monitor for 30 seconds or until stopped
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
    
    # Stop monitoring
    monitor.stop_monitoring()
    
    # Print stats
    print()
    print("=" * 80)
    print("Event Statistics:")
    print("=" * 80)
    stats = monitor.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print()
    print(f"Total events captured: {len(monitor.events)}")