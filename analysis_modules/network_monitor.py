"""
Network Monitor Module
Handles network connection monitoring and analysis
"""

import psutil
import threading
import time
from datetime import datetime


class NetworkMonitor:
    def __init__(self):
        """Initialize Network Monitor"""
        self.monitored_connections = {}
        self.monitoring_active = False
        self.monitoring_thread = None
        self.connection_callbacks = []
        self.known_connections = set()

        # Suspicious ports and IPs
        self.suspicious_ports = {
            4444, 5555, 6666, 7777,  # Common backdoor ports
            1337, 31337,  # Leet ports
            6667, 6668, 6669,  # IRC
            1234, 12345, 54321,  # Common trojan ports
            3389,  # RDP (can be suspicious if external)
        }

        # Private IP ranges (for reference)
        self.private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255')
        ]

    def register_connection_callback(self, callback):
        """Register callback for new connections"""
        self.connection_callbacks.append(callback)

    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring_active:
            print("Network monitoring already active")
            return

        self.monitoring_active = True
        self.known_connections = self._get_current_connections()

        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        print("Network monitoring started")

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)
        print("Network monitoring stopped")

    def _get_current_connections(self):
        """Get current connection identifiers"""
        connections = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_id = (
                    conn.laddr.ip if conn.laddr else None,
                    conn.laddr.port if conn.laddr else None,
                    conn.raddr.ip if conn.raddr else None,
                    conn.raddr.port if conn.raddr else None,
                    conn.status
                )
                connections.add(conn_id)
        except:
            pass
        return connections

    def _monitoring_loop(self):
        """Background monitoring loop for network connections"""
        while self.monitoring_active:
            try:
                current_connections = self._get_current_connections()
                new_connections = current_connections - self.known_connections

                for conn_id in new_connections:
                    # Get full connection info
                    for conn in psutil.net_connections(kind='inet'):
                        test_id = (
                            conn.laddr.ip if conn.laddr else None,
                            conn.laddr.port if conn.laddr else None,
                            conn.raddr.ip if conn.raddr else None,
                            conn.raddr.port if conn.raddr else None,
                            conn.status
                        )

                        if test_id == conn_id:
                            conn_info = self._process_connection(conn)

                            # Notify callbacks if suspicious
                            if conn_info.get('suspicious'):
                                for callback in self.connection_callbacks:
                                    try:
                                        callback(conn_info)
                                    except Exception as e:
                                        print(f"Error in connection callback: {e}")
                            break

                self.known_connections = current_connections
                time.sleep(3)  # Check every 3 seconds

            except Exception as e:
                print(f"Error in network monitoring loop: {e}")
                time.sleep(5)

    def _process_connection(self, conn):
        """Process and categorize a connection"""
        conn_info = {
            'type': conn.type.name if hasattr(conn, 'type') else 'UNKNOWN',
            'local_ip': conn.laddr.ip if conn.laddr else 'N/A',
            'local_port': conn.laddr.port if conn.laddr else 0,
            'remote_ip': conn.raddr.ip if conn.raddr else 'N/A',
            'remote_port': conn.raddr.port if conn.raddr else 0,
            'status': conn.status,
            'process_name': 'Unknown',
            'process_pid': conn.pid if hasattr(conn, 'pid') and conn.pid else 0,
            'process_path': 'N/A',  # FIXED: Add process path
            'suspicious': False,
            'timestamp': datetime.now().isoformat()
        }

        # Get process information
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                conn_info['process_name'] = proc.name()
                # FIXED: Get process file path
                try:
                    conn_info['process_path'] = proc.exe() if proc.exe() else 'N/A'
                except:
                    conn_info['process_path'] = 'N/A'
            except:
                pass

        # Check if suspicious
        conn_info['suspicious'] = self._is_suspicious(conn_info)

        # Store in monitored connections
        conn_key = f"{conn_info['local_ip']}:{conn_info['local_port']}-{conn_info['remote_ip']}:{conn_info['remote_port']}"
        self.monitored_connections[conn_key] = conn_info

        return conn_info

    def _is_suspicious(self, conn_info):
        """Determine if a connection is suspicious"""
        suspicious = False

        # Check remote port
        if conn_info['remote_port'] in self.suspicious_ports:
            suspicious = True

        # Check local port
        if conn_info['local_port'] in self.suspicious_ports:
            suspicious = True

        # Check if connecting to non-private IP on suspicious port
        remote_ip = conn_info['remote_ip']
        if remote_ip != 'N/A' and not self._is_private_ip(remote_ip):
            if conn_info['remote_port'] in self.suspicious_ports:
                suspicious = True

        return suspicious

    def _is_private_ip(self, ip_str):
        """Check if IP is in private range"""
        try:
            parts = [int(x) for x in ip_str.split('.')]
            if len(parts) != 4:
                return False

            # Check common private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True

            return False
        except:
            return False

    def get_all_connections(self, filter_criteria=None):
        """
        Get all current network connections
        FIXED: Added filtering support

        Args:
            filter_criteria: Dict with keys like 'process', 'port', 'ip', 'status'
        """
        connections = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'type': conn.type.name if hasattr(conn, 'type') else 'UNKNOWN',
                    'local_ip': conn.laddr.ip if conn.laddr else 'N/A',
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': conn.raddr.ip if conn.raddr else 'N/A',
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'status': conn.status,
                    'process_name': 'Unknown',
                    'process_pid': conn.pid if hasattr(conn, 'pid') and conn.pid else 0,
                    'process_path': 'N/A',  # FIXED: Add process path
                    'suspicious': False
                }

                # Get process info
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        conn_info['process_name'] = proc.name()
                        # FIXED: Get process file path
                        try:
                            conn_info['process_path'] = proc.exe() if proc.exe() else 'N/A'
                        except:
                            conn_info['process_path'] = 'N/A'
                    except:
                        pass

                conn_info['suspicious'] = self._is_suspicious(conn_info)

                # FIXED: Apply filtering
                if filter_criteria:
                    if not self._matches_filter(conn_info, filter_criteria):
                        continue

                connections.append(conn_info)

        except Exception as e:
            print(f"Error getting connections: {e}")

        return connections

    def _matches_filter(self, conn_info, criteria):
        """
        Check if connection matches filter criteria
        FIXED: Implement filtering logic
        """
        # Filter by process name
        if 'process' in criteria and criteria['process']:
            if criteria['process'].lower() not in conn_info['process_name'].lower():
                return False

        # Filter by IP (local or remote)
        if 'ip' in criteria and criteria['ip']:
            if criteria['ip'] not in conn_info['local_ip'] and criteria['ip'] not in conn_info['remote_ip']:
                return False

        # Filter by port (local or remote)
        if 'port' in criteria and criteria['port']:
            try:
                port = int(criteria['port'])
                if port != conn_info['local_port'] and port != conn_info['remote_port']:
                    return False
            except:
                pass

        # Filter by status
        if 'status' in criteria and criteria['status']:
            if criteria['status'].upper() not in conn_info['status'].upper():
                return False

        # Filter by suspicious flag
        if 'suspicious_only' in criteria and criteria['suspicious_only']:
            if not conn_info['suspicious']:
                return False

        return True

    def get_connection_summary(self):
        """Get summary statistics of network connections"""
        connections = self.get_all_connections()

        summary = {
            'total_connections': len(connections),
            'active_connections': len([c for c in connections if c['status'] == 'ESTABLISHED']),
            'suspicious_connections': len([c for c in connections if c['suspicious']]),
            'unique_remote_ips': len(set(c['remote_ip'] for c in connections if c['remote_ip'] != 'N/A')),
            'unique_local_ports': len(set(c['local_port'] for c in connections if c['local_port'] != 0))
        }

        return summary

    def get_process_connections(self, pid):
        """Get all connections for a specific process"""
        connections = []

        try:
            proc = psutil.Process(pid)
            for conn in proc.connections():
                conn_info = {
                    'type': conn.type.name if hasattr(conn, 'type') else 'UNKNOWN',
                    'local_ip': conn.laddr.ip if conn.laddr else 'N/A',
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': conn.raddr.ip if conn.raddr else 'N/A',
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'status': conn.status
                }
                connections.append(conn_info)

        except Exception as e:
            print(f"Error getting process connections: {e}")

        return connections
