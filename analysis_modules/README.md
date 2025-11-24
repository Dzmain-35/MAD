# MAD Analysis Modules

Modular analysis components for the MAD (Malware Analysis Dashboard) tool.

## Overview

This package contains three main analysis modules:

1. **YarWatch** - YARA-based file scanning and monitoring
2. **ProcessMonitor** - Real-time process monitoring with YARA scanning
3. **NetworkMonitor** - Network connection and traffic analysis

## Module Details

### 1. YarWatch (`yarwatch.py`)

YARA-based malware detection with detailed rule matching.

**Features:**
- Manual file scanning against YARA rules
- Detailed match information (offsets, matched strings, metadata)
- Automatic case integration
- Multiple file scanning with progress tracking
- Hash calculation (MD5, SHA256)

**Usage:**
```python
from analysis_modules import YarWatch

# Initialize
yarwatch = YarWatch(yara_rules_path="/path/to/rules", case_manager=case_mgr)

# Scan a single file
result = yarwatch.scan_file("malware.exe", add_to_case=True)

# Get formatted output
print(yarwatch.format_match_details(result))

# Scan multiple files
results = yarwatch.scan_multiple_files(
    file_paths=["file1.exe", "file2.dll"],
    progress_callback=lambda curr, total, name: print(f"{curr}/{total}: {name}")
)
```

**Output Format:**
```python
{
    "filename": "malware.exe",
    "file_path": "/path/to/malware.exe",
    "file_size": 123456,
    "md5": "abc123...",
    "sha256": "def456...",
    "scan_timestamp": "2025-11-19T10:30:00",
    "matches_found": 2,
    "detailed_matches": [
        {
            "rule_name": "Mal_Trojan_Generic",
            "namespace": "rule_0_malware",
            "tags": ["trojan", "malware"],
            "strings": [
                {
                    "identifier": "$string1",
                    "instances": [
                        {
                            "offset": 1024,
                            "matched_data": "suspicious_string_here",
                            "length": 20
                        }
                    ]
                }
            ],
            "meta": {
                "author": "Analyst",
                "description": "Generic trojan detection"
            }
        }
    ],
    "threat_detected": True
}
```

### 2. ProcessMonitor (`process_monitor.py`)

Real-time process monitoring with automatic YARA scanning of new processes.

**Features:**
- Real-time monitoring of new processes
- Automatic YARA scanning of new process executables
- Process tree visualization
- String extraction from process executables
- Process details (CPU, memory, connections, parent/child relationships)
- Process termination capability

**Usage:**
```python
from analysis_modules import ProcessMonitor

# Initialize
monitor = ProcessMonitor(yara_rules_path="/path/to/rules")

# Register callback for new processes
def on_new_process(proc_info):
    if proc_info.get('threat_detected'):
        print(f"THREAT: {proc_info['name']} (PID {proc_info['pid']})")

monitor.register_process_callback(on_new_process)

# Start monitoring
monitor.start_monitoring()

# Get all current processes
processes = monitor.get_all_processes()

# Get detailed info for specific PID
info = monitor.get_process_info(1234)

# Scan a specific process
scan_result = monitor.scan_process(1234)

# Extract strings from process
strings = monitor.extract_strings_from_process(1234, min_length=4, limit=1000)

# Get process tree
tree = monitor.get_process_tree()

# Kill a process (use with caution!)
monitor.kill_process(1234)

# Stop monitoring
monitor.stop_monitoring()
```

**Process Info Format:**
```python
{
    "pid": 1234,
    "name": "suspicious.exe",
    "exe": "C:\\path\\to\\suspicious.exe",
    "cmdline": "suspicious.exe -arg1 -arg2",
    "create_time": "2025-11-19T10:30:00",
    "status": "running",
    "username": "SYSTEM",
    "cpu_percent": 15.2,
    "memory_info": {"rss": 10485760, "vms": 20971520},
    "num_threads": 5,
    "parent_pid": 888,
    "parent_name": "explorer.exe",
    "connections": [
        {
            "laddr": "192.168.1.100:49152",
            "raddr": "1.2.3.4:80",
            "status": "ESTABLISHED"
        }
    ],
    "threat_detected": True,
    "yara_scan": {
        "matches_found": 1,
        "detailed_matches": [...]
    }
}
```

### 3. NetworkMonitor (`network_monitor.py`)

Network connection monitoring with suspicious activity detection.

**Features:**
- Real-time network connection monitoring
- Suspicious connection detection (backdoor ports, suspicious IPs)
- Connection history tracking
- Process-to-connection mapping
- Port scan detection
- Private/public IP filtering
- Hostname resolution

**Usage:**
```python
from analysis_modules import NetworkMonitor

# Initialize
monitor = NetworkMonitor()

# Register callback for new connections
def on_new_connection(conn):
    if conn.get('suspicious'):
        print(f"SUSPICIOUS: {conn['remote_ip']}:{conn['remote_port']}")
        print(f"Reason: {conn['suspicious_reason']}")

monitor.register_connection_callback(on_new_connection)

# Start monitoring
monitor.start_monitoring(interval=1.0)  # Check every 1 second

# Get all current connections
connections = monitor.get_all_connections()

# Get suspicious connections only
suspicious = monitor.get_suspicious_connections()

# Get connections for specific process
proc_connections = monitor.get_connections_by_process(pid=1234)

# Get connections by IP
ip_connections = monitor.get_connections_by_ip("1.2.3.4")

# Add IP to suspicious list
monitor.add_suspicious_ip("1.2.3.4")

# Detect port scanning
port_scans = monitor.detect_port_scan(threshold=10)

# Get statistics
stats = monitor.get_connection_summary()

# Export connection history
history = monitor.export_connection_history(limit=100)

# Stop monitoring
monitor.stop_monitoring()
```

**Connection Info Format:**
```python
{
    "family": "IPv4",
    "type": "TCP",
    "local_ip": "192.168.1.100",
    "local_port": 49152,
    "remote_ip": "1.2.3.4",
    "remote_port": 80,
    "remote_hostname": "example.com",
    "status": "ESTABLISHED",
    "pid": 1234,
    "process_name": "chrome.exe",
    "process_exe": "C:\\Program Files\\Chrome\\chrome.exe",
    "timestamp": "2025-11-19T10:30:00",
    "first_seen": "2025-11-19T10:30:00",
    "last_seen": "2025-11-19T10:30:15",
    "packet_count": 150,
    "suspicious": True,
    "suspicious_reason": "Suspicious port: 4444"
}
```

## Integration with GUI

Each module is designed to be imported into the main GUI application:

```python
# In gui.py
from analysis_modules import YarWatch, ProcessMonitor, NetworkMonitor

class ForensicAnalysisGUI:
    def __init__(self):
        # Initialize modules
        self.yarwatch = YarWatch(
            yara_rules_path=self.case_manager.yara_rules_path,
            case_manager=self.case_manager
        )
        
        self.process_monitor = ProcessMonitor(
            yara_rules_path=self.case_manager.yara_rules_path
        )
        
        self.network_monitor = NetworkMonitor()
        
        # Register callbacks
        self.process_monitor.register_process_callback(self.on_new_process)
        self.network_monitor.register_connection_callback(self.on_new_connection)
```

## Requirements

```
psutil>=5.9.0
yara-python>=4.3.0
```

## Threading and Performance

- **YarWatch**: Synchronous by design, use threading wrapper if needed
- **ProcessMonitor**: Background thread monitors processes every 500ms
- **NetworkMonitor**: Background thread monitors connections at configurable interval

All monitors use daemon threads that automatically stop when the main application exits.

## Security Considerations

- Process Monitor requires elevated privileges to access some process information
- Network Monitor may require admin rights to see all connections
- All modules are designed for use in isolated VM environments
- NEVER use on production systems without proper safeguards

## Suspicious Activity Detection

### Process Monitor Triggers:
- New processes with YARA rule matches
- Processes from suspicious locations
- Unsigned processes making network connections

### Network Monitor Triggers:
- Connections to known backdoor ports (4444, 31337, etc.)
- Suspicious processes with external connections
- Port scanning behavior
- Connections to blacklisted IPs

## Future Enhancements

- [ ] Machine learning-based anomaly detection
- [ ] Integration with threat intelligence feeds
- [ ] Real-time memory dumping for processes
- [ ] Packet capture integration (PCAP)
- [ ] Automated IOC extraction
- [ ] Report generation for all modules
- [ ] DNS query logging
- [ ] SSL/TLS certificate inspection

## Troubleshooting

**YARA rules not loading:**
- Check path exists and contains .yara or .yar files
- Verify YARA rules syntax
- Ensure yara-python is installed correctly

**Process scanning fails:**
- Run as Administrator
- Some processes are protected by Windows
- Antivirus may block process access

**Network monitoring shows no connections:**
- Run as Administrator
- Check Windows Firewall settings
- Verify psutil is installed correctly

## License

Part of the MAD (Malware Analysis Dashboard) project.