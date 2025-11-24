"""
Network Monitor Module - Network Connection and Traffic Analysis
Monitors active connections, DNS queries, and detects suspicious activity
"""

import psutil
import socket
import threading
import time
from typing import Dict, List, Optional, Callable, Set
from datetime import datetime
from collections import defaultdict
import re


class NetworkMonitor:
    def __init__(self):
        """Initialize Network Monitor"""
        self.is_monitoring = False
        self.monitor_thread = None
        self.connection_callbacks = []
        
        # Track connections
        self.active_connections: Dict[str, Dict] = {}
        self.connection_history: List[Dict] = []
        self.suspicious_ips: Set[str] = set()
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "suspicious_connections": 0,
            "unique_remote_ips": set(),
            "unique_local_ports": set()
        }
        
        # Suspicious indicators
        self.suspicious_ports = {
            4444, 4445, 5555, 6666, 6667, 8080, 8888, 9090,  # Common backdoor ports
            31337, 12345, 54321,  # Known trojan ports
            1337, 3389  # RDP and other remote access
        }
        
        self.suspicious_port_ranges = [
            (range(6660, 6670), "IRC"),  # IRC ports
            (range(666, 668), "Doom/Evil ports"),
            (range(1000, 1025), "Privileged ports")
        ]
    
    def start_monitoring(self, interval: float = 1.0):
        """
        Start network monitoring
        
        Args:
            interval: Monitoring interval in seconds
        """
        if self.is_monitoring:
            print("Network monitoring already active")
            return False
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        print("Network monitoring started")
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self.is_monitoring:
            return False
        
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("Network monitoring stopped")
        return True
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop - runs in separate thread"""
        print("Network monitoring loop started")
        
        while self.is_monitoring:
            try:
                current_connections = self.get_all_connections()
                
                # Update active connections
                current_conn_ids = set()
                
                for conn in current_connections:
                    conn_id = self._get_connection_id(conn)
                    current_conn_ids.add(conn_id)
                    
                    # New connection detected
                    if conn_id not in self.active_connections:
                        conn['first_seen'] = datetime.now().isoformat()
                        conn['packet_count'] = 0
                        
                        # Check if suspicious
                        if self._is_suspicious_connection(conn):
                            conn['suspicious'] = True
                            self.stats['suspicious_connections'] += 1
                            print(f"⚠️ SUSPICIOUS CONNECTION: {conn.get('remote_ip')}:{conn.get('remote_port')} - {conn.get('suspicious_reason', 'Unknown')}")
                        
                        self.active_connections[conn_id] = conn
                        self.connection_history.append(conn.copy())
                        self.stats['total_connections'] += 1
                        
                        # Trigger callbacks
                        for callback in self.connection_callbacks:
                            callback(conn)
                    else:
                        # Update existing connection
                        self.active_connections[conn_id]['packet_count'] += 1
                        self.active_connections[conn_id]['last_seen'] = datetime.now().isoformat()
                
                # Remove closed connections
                closed_connections = set(self.active_connections.keys()) - current_conn_ids
                for conn_id in closed_connections:
                    del self.active_connections[conn_id]
                
                # Update stats
                self.stats['active_connections'] = len(self.active_connections)
                
                time.sleep(interval)
                
            except Exception as e:
                print(f"Error in network monitoring loop: {e}")
                time.sleep(1)
    
    def get_all_connections(self) -> List[Dict]:
        """
        Get all current network connections
        
        Returns:
            List of connection dictionaries
        """
        connections = []
        
        try:
            # Get all network connections
            for conn in psutil.net_connections(kind='inet'):
                try:
                    conn_info = {
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'local_ip': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_ip': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Get process info if available
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            conn_info['process_name'] = proc.name()
                            conn_info['process_exe'] = proc.exe()
                        except:
                            conn_info['process_name'] = 'Unknown'
                            conn_info['process_exe'] = 'Unknown'
                    
                    # Try to resolve hostname (non-blocking)
                    if conn_info['remote_ip'] and not self._is_private_ip(conn_info['remote_ip']):
                        try:
                            # Quick hostname lookup with timeout
                            hostname = socket.gethostbyaddr(conn_info['remote_ip'])
                            conn_info['remote_hostname'] = hostname[0]
                        except:
                            conn_info['remote_hostname'] = None
                    
                    connections.append(conn_info)
                    
                    # Update stats
                    if conn_info['remote_ip']:
                        self.stats['unique_remote_ips'].add(conn_info['remote_ip'])
                    if conn_info['local_port']:
                        self.stats['unique_local_ports'].add(conn_info['local_port'])
                
                except Exception as e:
                    continue
        
        except Exception as e:
            print(f"Error getting network connections: {e}")
        
        return connections
    
    def _get_connection_id(self, conn: Dict) -> str:
        """Generate unique ID for a connection"""
        return f"{conn.get('local_ip')}:{conn.get('local_port')}-{conn.get('remote_ip')}:{conn.get('remote_port')}-{conn.get('type')}"
    
    def _is_suspicious_connection(self, conn: Dict) -> bool:
        """
        Check if a connection is suspicious
        
        Args:
            conn: Connection dictionary
            
        Returns:
            True if suspicious
        """
        reasons = []
        
        # Check remote port
        if conn.get('remote_port') in self.suspicious_ports:
            reasons.append(f"Suspicious port: {conn['remote_port']}")
        
        # Check port ranges
        for port_range, description in self.suspicious_port_ranges:
            if conn.get('remote_port') in port_range:
                reasons.append(f"{description} port: {conn['remote_port']}")
        
        # Check for connections to suspicious IPs
        remote_ip = conn.get('remote_ip')
        if remote_ip:
            # Check if IP is in suspicious list
            if remote_ip in self.suspicious_ips:
                reasons.append(f"Known suspicious IP: {remote_ip}")
            
            # Check for non-standard IP patterns
            if self._is_suspicious_ip_pattern(remote_ip):
                reasons.append(f"Suspicious IP pattern")
        
        # Check for suspicious process names
        process_name = conn.get('process_name', '').lower()
        suspicious_process_names = [
            'powershell', 'cmd', 'wscript', 'cscript', 'rundll32',
            'regsvr32', 'mshta', 'certutil'
        ]
        if any(susp in process_name for susp in suspicious_process_names):
            if conn.get('remote_ip') and not self._is_private_ip(conn['remote_ip']):
                reasons.append(f"Suspicious process with external connection: {process_name}")
        
        if reasons:
            conn['suspicious_reason'] = "; ".join(reasons)
            return True
        
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            # Check private IP ranges
            if parts[0] == '10':
                return True
            if parts[0] == '172' and 16 <= int(parts[1]) <= 31:
                return True
            if parts[0] == '192' and parts[1] == '168':
                return True
            if parts[0] == '127':  # Loopback
                return True
            
            return False
        except:
            return False
    
    def _is_suspicious_ip_pattern(self, ip: str) -> bool:
        """Check for suspicious IP patterns"""
        # Check for IPs with suspicious patterns
        # (e.g., sequential numbers, all same digits, etc.)
        try:
            parts = [int(p) for p in ip.split('.')]
            
            # Check for sequential octets
            if parts == sorted(parts) or parts == sorted(parts, reverse=True):
                if len(set(parts)) == len(parts):  # All different
                    return True
            
            # Check for all same octets
            if len(set(parts)) == 1:
                return True
            
        except:
            pass
        
        return False
    
    def get_connection_summary(self) -> Dict:
        """
        Get summary of network activity
        
        Returns:
            Dictionary with network statistics
        """
        return {
            'total_connections': self.stats['total_connections'],
            'active_connections': self.stats['active_connections'],
            'suspicious_connections': self.stats['suspicious_connections'],
            'unique_remote_ips': len(self.stats['unique_remote_ips']),
            'unique_local_ports': len(self.stats['unique_local_ports']),
            'connection_history_size': len(self.connection_history)
        }
    
    def get_suspicious_connections(self) -> List[Dict]:
        """Get all suspicious connections"""
        return [conn for conn in self.active_connections.values() 
                if conn.get('suspicious', False)]
    
    def get_connections_by_process(self, pid: int) -> List[Dict]:
        """
        Get all connections for a specific process
        
        Args:
            pid: Process ID
            
        Returns:
            List of connections
        """
        return [conn for conn in self.active_connections.values() 
                if conn.get('pid') == pid]
    
    def get_connections_by_ip(self, ip: str) -> List[Dict]:
        """
        Get all connections to/from a specific IP
        
        Args:
            ip: IP address
            
        Returns:
            List of connections
        """
        return [conn for conn in self.active_connections.values() 
                if conn.get('remote_ip') == ip or conn.get('local_ip') == ip]
    
    def add_suspicious_ip(self, ip: str):
        """Add an IP to the suspicious list"""
        self.suspicious_ips.add(ip)
        print(f"Added {ip} to suspicious IP list")
    
    def remove_suspicious_ip(self, ip: str):
        """Remove an IP from the suspicious list"""
        if ip in self.suspicious_ips:
            self.suspicious_ips.remove(ip)
            print(f"Removed {ip} from suspicious IP list")
    
    def export_connection_history(self, limit: int = 100) -> List[Dict]:
        """
        Export connection history
        
        Args:
            limit: Maximum number of connections to export
            
        Returns:
            List of connection dictionaries
        """
        return self.connection_history[-limit:]
    
    def register_connection_callback(self, callback: Callable):
        """
        Register a callback for new connections
        
        Args:
            callback: Function to call with connection info
        """
        self.connection_callbacks.append(callback)
    
    def get_bandwidth_by_process(self) -> Dict[int, Dict]:
        """
        Get approximate bandwidth usage by process
        (Based on connection count - not actual bytes)
        
        Returns:
            Dictionary mapping PID to connection stats
        """
        process_stats = defaultdict(lambda: {'connection_count': 0, 'process_name': 'Unknown'})
        
        for conn in self.active_connections.values():
            pid = conn.get('pid')
            if pid:
                process_stats[pid]['connection_count'] += 1
                process_stats[pid]['process_name'] = conn.get('process_name', 'Unknown')
        
        return dict(process_stats)
    
    def detect_port_scan(self, threshold: int = 10) -> List[Dict]:
        """
        Detect potential port scanning activity
        
        Args:
            threshold: Number of connection attempts to trigger alert
            
        Returns:
            List of suspicious activities
        """
        # Group connections by source IP and count unique destination ports
        ip_port_map = defaultdict(set)
        
        for conn in self.connection_history[-1000:]:  # Check last 1000 connections
            remote_ip = conn.get('remote_ip')
            remote_port = conn.get('remote_port')
            if remote_ip and remote_port:
                ip_port_map[remote_ip].add(remote_port)
        
        # Find IPs connecting to many ports
        suspicious = []
        for ip, ports in ip_port_map.items():
            if len(ports) >= threshold:
                suspicious.append({
                    'ip': ip,
                    'port_count': len(ports),
                    'ports': list(ports),
                    'alert': 'Potential port scan detected'
                })
        
        return suspicious


# Example usage for testing
if __name__ == "__main__":
    monitor = NetworkMonitor()
    
    # Get current connections
    connections = monitor.get_all_connections()
    print(f"Found {len(connections)} network connections")
    
    # Show first few connections
    for conn in connections[:5]:
        print(f"\n{conn['type']} connection:")
        print(f"  Local: {conn['local_ip']}:{conn['local_port']}")
        print(f"  Remote: {conn['remote_ip']}:{conn['remote_port']}")
        print(f"  Process: {conn.get('process_name', 'Unknown')} (PID {conn.get('pid')})")
        print(f"  Status: {conn['status']}")