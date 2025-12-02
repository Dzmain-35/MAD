# Process Scanning Alternatives - Enhanced Access Without Admin Rights

This document describes the enhanced process scanning capabilities in MAD that allow access to system and protected processes without requiring full administrator privileges.

## Overview

MAD now implements a **multi-tiered access strategy** that gracefully degrades through multiple methods to maximize process information retrieval, even for protected system processes.

## Problem Statement

When scanning processes on Windows, especially system processes, you may encounter "Access Denied" errors due to:
- Protected Process Light (PPL) protection
- System process isolation
- Insufficient privileges
- Security boundaries

Traditional solutions require running as administrator, which isn't always possible or desirable.

## Our Solution: Multi-Tiered Access Strategy

MAD now implements multiple complementary methods that work together to maximize process visibility:

```
┌─────────────────────────────────────────────────────────┐
│             Multi-Tiered Access Strategy                 │
└─────────────────────────────────────────────────────────┘
                          ↓
    ┌───────────────────────────────────────┐
    │  Tier 1: Full Process Access          │
    │  (psutil + PROCESS_QUERY_INFORMATION  │
    │   + PROCESS_VM_READ)                  │
    │  Best case: Full memory access        │
    └───────────────────────────────────────┘
                          ↓ (if Access Denied)
    ┌───────────────────────────────────────┐
    │  Tier 2: Limited Query Access         │
    │  (PROCESS_QUERY_LIMITED_INFORMATION)  │
    │  Works on most protected processes    │
    │  Basic info without memory access     │
    └───────────────────────────────────────┘
                          ↓ (if Access Denied)
    ┌───────────────────────────────────────┐
    │  Tier 3: WMI Fallback                 │
    │  (Windows Management Instrumentation) │
    │  Works on system processes            │
    │  Rich process metadata                │
    └───────────────────────────────────────┘
                          ↓ (if unavailable)
    ┌───────────────────────────────────────┐
    │  Tier 4: Sysmon Process Cache         │
    │  (Historical process data)            │
    │  Cached from ProcessCreate events     │
    │  Includes command line, parent info   │
    └───────────────────────────────────────┘
```

## New Features

### 1. PROCESS_QUERY_LIMITED_INFORMATION Support

**File**: `analysis_modules/memory_string_extractor.py`

The memory string extractor now attempts multiple access levels:

```python
# Tier 1: Try full access (best case)
h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

# Tier 2: Try limited access (for protected processes)
if not h_process:
    h_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
```

**Benefits**:
- Access to basic process information even for protected processes
- No admin rights required
- Works on most system processes

**Data Available with Limited Access**:
- Process name
- Executable path
- Creation time
- Exit code
- Basic process information

**Limitations**:
- Cannot read process memory
- Cannot enumerate memory regions
- No string extraction

### 2. WMI-Based Process Info Module

**File**: `analysis_modules/wmi_process_info.py`

New module providing WMI-based process information retrieval as a fallback method.

**Usage**:
```python
from analysis_modules.wmi_process_info import WMIProcessInfo

wmi_info = WMIProcessInfo(verbose=True)

# Get process info for PID
info = wmi_info.get_process_info(1234)

# Get all processes
all_procs = wmi_info.get_all_processes()

# Get processes by name
notepad_procs = wmi_info.get_process_by_name("notepad.exe")

# Get loaded modules
modules = wmi_info.get_process_modules(1234)
```

**Benefits**:
- Works on protected system processes
- No admin rights required (for basic info)
- Rich metadata including owner, parent process, command line
- Can query historical process data

**Data Available**:
- PID, Name, Executable path
- Command line arguments
- Parent process ID and name
- Thread count, handle count
- Working set size
- Process owner (username)
- Creation date
- Priority, Session ID

**Requirements**:
- Install WMI module: `pip install wmi`
- Windows platform only

### 3. SeDebugPrivilege Helper

**File**: `analysis_modules/privilege_helper.py`

Utility for enabling SeDebugPrivilege at runtime without full admin elevation.

**Usage**:
```python
from analysis_modules.privilege_helper import enable_debug_privilege, is_admin

# Check if running as admin
if is_admin():
    print("Running as administrator")

# Enable SeDebugPrivilege for current process
if enable_debug_privilege():
    print("SeDebugPrivilege enabled - enhanced process access")
else:
    print("SeDebugPrivilege not available")
```

**Benefits**:
- Enhanced process access without full UAC elevation
- Works for users in the Administrators group
- Granular privilege management
- Can enable multiple privileges

**Available Privileges**:
- `SeDebugPrivilege` - Debug other processes
- `SeBackupPrivilege` - Backup files and directories
- `SeRestorePrivilege` - Restore files and directories
- `SeTakeOwnershipPrivilege` - Take ownership of objects

**Requirements**:
- User account must have the privilege assigned (usually Administrators group)
- Windows platform only

### 4. Enhanced Process Monitor with Integrated Fallbacks

**File**: `analysis_modules/process_monitor.py`

The main ProcessMonitor class now automatically integrates all access methods:

```python
class ProcessMonitor:
    def __init__(self, yara_rules_path: str):
        # Automatically initializes:
        # 1. Memory extractor (with multi-tiered access)
        # 2. WMI fallback
        # 3. Privilege helper (enables SeDebugPrivilege)
        # 4. Sysmon integration
```

**Automatic Access Strategy**:

When retrieving process information:

1. **Try psutil** (fastest, most detailed)
   - If successful: Returns full process info
   - If AccessDenied: Falls through to next tier

2. **Try WMI** (broader access)
   - Queries Win32_Process for the PID
   - Returns rich metadata
   - If AccessDenied/unavailable: Falls through

3. **Return None** (truly inaccessible)
   - Logs warning about protected process
   - Continues monitoring other processes

**Status Messages**:
```
✓ Memory string extractor initialized (verbose mode enabled)
✓ WMI process info initialized (fallback for protected processes)
✓ SeDebugPrivilege enabled (enhanced process access)
ℹ Using WMI fallback for protected process PID 4
```

### 5. Sysmon Process Info Cache

**File**: `analysis_modules/sysmon_parser.py`

Sysmon events now cache process information for later retrieval:

```python
# Automatically caches ProcessCreate events (Event ID 1)
monitor = SysmonLogMonitor()
monitor.start_monitoring()

# Retrieve cached process info
cached_info = monitor.get_cached_process_info(1234)

# Get all cached processes
all_cached = monitor.get_all_cached_processes()

# Clear cache
monitor.clear_process_cache()
```

**Benefits**:
- Historical process data even after process termination
- Includes command line arguments
- Parent process information
- User context
- No need for direct process access

**Data Available**:
- PID, Name, Image path
- Command line
- User
- Creation time
- Parent PID and image
- Access method: 'sysmon_cache'

**Cache Management**:
- Maximum 1000 processes cached
- Automatically evicts oldest 10% when full
- Cleared on monitor restart

## Usage Examples

### Example 1: Scanning a Protected System Process

```python
from analysis_modules.process_monitor import ProcessMonitor

# Initialize monitor
monitor = ProcessMonitor("yara_rules/")

# Try to get info on protected process (e.g., PID 4 - System)
info = monitor.get_process_info(4)

if info:
    print(f"Process: {info['name']}")
    print(f"Access method: {info['access_method']}")  # Will show 'wmi' for protected processes
    print(f"Command line: {info.get('cmdline', 'N/A')}")
    print(f"User: {info.get('username', 'N/A')}")
```

### Example 2: Memory Extraction with Fallback

```python
from analysis_modules.memory_string_extractor import MemoryStringExtractor

extractor = MemoryStringExtractor(verbose=True)

# Try to extract strings from process
result = extractor.extract_strings_from_memory(pid=1234)

if result['access_level'] == 'full':
    print("Full access - memory strings extracted")
    print(f"Strings found: {len(result['strings']['ascii'])}")
elif result['access_level'] == 'limited':
    print("Limited access - cannot read memory")
    print("Process information available, but no memory access")
else:
    print("Access denied - protected system process")
```

### Example 3: Combining Methods for Maximum Coverage

```python
from analysis_modules.process_monitor import ProcessMonitor
from analysis_modules.wmi_process_info import WMIProcessInfo

monitor = ProcessMonitor("yara_rules/")
wmi_info = WMIProcessInfo()

# Get list of all processes via WMI (works for system processes)
all_processes = wmi_info.get_all_processes()

for proc in all_processes:
    pid = proc['pid']

    # Try to scan with YARA
    scan_result = monitor.scan_process_plugins(pid)

    if scan_result:
        print(f"Scanned PID {pid}: {proc['name']}")
    else:
        print(f"Could not scan PID {pid} (limited access)")
```

## Installation Requirements

### Required (Core Functionality)
```bash
pip install psutil
pip install yara-python
```

### Optional (Enhanced Access)
```bash
# For WMI fallback support
pip install wmi

# For Windows event log support (Sysmon)
pip install pywin32
```

## Comparison of Access Methods

| Feature | psutil | Limited Query | WMI | Sysmon Cache |
|---------|--------|---------------|-----|--------------|
| Speed | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| System Process Access | ❌ | ✅ | ✅ | ✅ |
| Memory Access | ✅ | ❌ | ❌ | ❌ |
| Command Line | ✅ | ❌ | ✅ | ✅ |
| Parent Process | ✅ | ❌ | ✅ | ✅ |
| Network Connections | ✅ | ❌ | ⚠️ | ❌ |
| Real-time | ✅ | ✅ | ✅ | ✅ |
| Historical Data | ❌ | ❌ | ❌ | ✅ |
| Admin Required | ⚠️ | ❌ | ❌ | ❌ |
| Windows Only | ❌ | ✅ | ✅ | ✅ |

Legend: ✅ Full Support | ⚠️ Partial | ❌ Not Available

## Troubleshooting

### "WMI process info not available"

**Cause**: WMI Python module not installed

**Solution**:
```bash
pip install wmi
```

### "SeDebugPrivilege not available"

**Cause**: User account doesn't have SeDebugPrivilege assigned

**Solution**:
- Run as a user in the Administrators group
- Or: Run the application as administrator
- Or: Assign SeDebugPrivilege via Group Policy

### "Access denied for PID X (protected system process)"

**Cause**: Process is protected by PPL or system isolation

**Outcome**:
- This is expected for certain critical system processes
- MAD will continue monitoring other accessible processes
- Consider using Sysmon cache for historical data on this process

### "Sysmon not available"

**Cause**: Sysmon not installed or not running

**Solution**:
1. Download Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Install: `sysmon.exe -accepteula -i`
3. Configure with a config file for better coverage
4. Restart MAD

## Best Practices

1. **Start with SeDebugPrivilege**: Always attempt to enable it at startup for maximum access

2. **Use WMI for System Processes**: When you specifically need to monitor system processes, WMI is more reliable than direct API access

3. **Enable Sysmon**: For comprehensive monitoring, install and configure Sysmon to capture ProcessCreate events

4. **Monitor Access Methods**: Check the `access_method` field in process info to understand which method was used

5. **Handle None Gracefully**: Some processes will always be inaccessible - design your analysis to handle None returns

6. **Cache Aggressively**: Use the Sysmon cache for historical process data, especially for short-lived processes

## Performance Considerations

### Tier 1 (psutil + Full Access)
- **Latency**: <1ms per process
- **Throughput**: Thousands of processes/second
- **Best for**: Regular processes, detailed analysis

### Tier 2 (Limited Query)
- **Latency**: <5ms per process
- **Throughput**: Hundreds of processes/second
- **Best for**: Protected processes, basic information

### Tier 3 (WMI)
- **Latency**: 10-50ms per process
- **Throughput**: Tens of processes/second
- **Best for**: System processes, rich metadata

### Tier 4 (Sysmon Cache)
- **Latency**: <1ms (in-memory lookup)
- **Throughput**: Thousands of lookups/second
- **Best for**: Historical data, terminated processes

**Recommendation**: Let MAD automatically choose the best method. The multi-tiered strategy optimizes for speed while maximizing access.

## Security Considerations

### SeDebugPrivilege
- Powerful privilege that allows reading memory of other processes
- Should only be enabled when necessary
- MAD only enables it for the current process, not system-wide
- Automatically cleaned up when process exits

### WMI Access
- Generally safe for read-only operations
- Terminating processes via WMI requires appropriate permissions
- MAD uses WMI only for information retrieval, not modification

### Process Caching
- Cached process info may contain sensitive data (command lines, usernames)
- Cache is stored in memory only, not persisted to disk
- Automatically limited to 1000 processes
- Cleared when monitoring stops

## Future Enhancements

Potential future improvements to process scanning:

1. **Native API Integration**: Use NtQuerySystemInformation for even better system process access

2. **ETW Kernel Tracing**: Add kernel-mode ETW tracing for low-level process events

3. **Performance Data Helper (PDH)**: Integrate PDH API for performance metrics

4. **Process Tree Reconstruction**: Build complete process trees using cached parent relationships

5. **Credential Caching**: Cache process credentials/tokens for quicker lookups

6. **Machine Learning Access Prediction**: Predict which access method will work based on process characteristics

## References

- [Microsoft Documentation - Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [WMI Win32_Process Class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process)
- [Windows Privileges](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)

## Contributing

If you have additional process access methods or improvements to the existing strategy, please contribute:

1. Add new access method to `analysis_modules/`
2. Integrate into `ProcessMonitor` class
3. Update this documentation
4. Add tests for the new method
5. Submit pull request

---

**Last Updated**: 2025-12-02
**Version**: 1.0
**Maintainer**: MAD Development Team
