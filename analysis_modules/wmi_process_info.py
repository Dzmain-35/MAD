"""
WMI-Based Process Information Retrieval
Provides fallback method for accessing process information when direct API access fails
Works on protected/system processes without admin privileges
"""

import platform
from typing import Dict, Optional, List
from datetime import datetime

# Check if running on Windows and import WMI
IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    try:
        import wmi
        WMI_AVAILABLE = True
    except ImportError:
        WMI_AVAILABLE = False
        wmi = None
else:
    WMI_AVAILABLE = False
    wmi = None


class WMIProcessInfo:
    """
    Retrieve process information using WMI (Windows Management Instrumentation)
    This provides access to system processes that may be protected from direct API access
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize WMI process info retriever

        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.wmi_connection = None

        if not IS_WINDOWS:
            raise RuntimeError("WMIProcessInfo requires Windows platform")

        if not WMI_AVAILABLE:
            raise RuntimeError("WMI module not available. Install with: pip install wmi")

        try:
            self.wmi_connection = wmi.WMI()
            if self.verbose:
                print("[WMI] Successfully initialized WMI connection")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize WMI: {e}")

    def get_process_info(self, pid: int) -> Optional[Dict]:
        """
        Get detailed process information via WMI

        Args:
            pid: Process ID

        Returns:
            Dictionary with process information or None if not found
        """
        if not self.wmi_connection:
            return None

        try:
            # Query for specific process
            processes = self.wmi_connection.Win32_Process(ProcessId=pid)

            if not processes:
                if self.verbose:
                    print(f"[WMI] Process {pid} not found")
                return None

            process = processes[0]

            # Build comprehensive process info
            info = {
                "pid": pid,
                "name": process.Name if process.Name else "N/A",
                "exe": process.ExecutablePath if process.ExecutablePath else "N/A",
                "cmdline": process.CommandLine if process.CommandLine else "N/A",
                "ppid": process.ParentProcessId if process.ParentProcessId else None,
                "access_method": "wmi",
                "creation_date": self._parse_wmi_datetime(process.CreationDate) if process.CreationDate else None,
                "thread_count": process.ThreadCount if process.ThreadCount else 0,
                "handle_count": process.HandleCount if process.HandleCount else 0,
                "working_set_size": process.WorkingSetSize if process.WorkingSetSize else 0,
                "priority": process.Priority if process.Priority else 0,
                "session_id": process.SessionId if process.SessionId else 0,
            }

            # Get process owner (username)
            try:
                owner_info = process.GetOwner()
                if owner_info and len(owner_info) >= 3:
                    domain = owner_info[2] if owner_info[2] else ""
                    user = owner_info[0] if owner_info[0] else ""
                    info["username"] = f"{domain}\\{user}" if domain else user
                else:
                    info["username"] = "N/A"
            except Exception:
                info["username"] = "N/A"

            # Get parent process name
            if process.ParentProcessId:
                try:
                    parent_processes = self.wmi_connection.Win32_Process(ProcessId=process.ParentProcessId)
                    if parent_processes:
                        info["parent_name"] = parent_processes[0].Name
                    else:
                        info["parent_name"] = None
                except Exception:
                    info["parent_name"] = None
            else:
                info["parent_name"] = None

            if self.verbose:
                print(f"[WMI] Successfully retrieved info for PID {pid}: {info['name']}")

            return info

        except Exception as e:
            if self.verbose:
                print(f"[WMI] Error getting process info for PID {pid}: {e}")
            return None

    def get_all_processes(self) -> List[Dict]:
        """
        Get information for all running processes

        Returns:
            List of process information dictionaries
        """
        if not self.wmi_connection:
            return []

        processes = []

        try:
            for process in self.wmi_connection.Win32_Process():
                if not process.ProcessId:
                    continue

                proc_info = {
                    "pid": process.ProcessId,
                    "name": process.Name if process.Name else "N/A",
                    "exe": process.ExecutablePath if process.ExecutablePath else "N/A",
                    "ppid": process.ParentProcessId if process.ParentProcessId else None,
                    "thread_count": process.ThreadCount if process.ThreadCount else 0,
                    "working_set_size": process.WorkingSetSize if process.WorkingSetSize else 0,
                }

                processes.append(proc_info)

            if self.verbose:
                print(f"[WMI] Retrieved info for {len(processes)} processes")

            return processes

        except Exception as e:
            if self.verbose:
                print(f"[WMI] Error getting all processes: {e}")
            return []

    def get_process_network_connections(self, pid: int) -> List[Dict]:
        """
        Get network connections for a specific process

        Args:
            pid: Process ID

        Returns:
            List of connection dictionaries
        """
        if not self.wmi_connection:
            return []

        connections = []

        try:
            # Query TCP connections
            for conn in self.wmi_connection.Win32_NetworkAdapterConfiguration():
                # Note: Win32_NetworkAdapterConfiguration doesn't provide per-process info
                # This is a limitation of WMI - would need to use netstat or other methods
                pass

            # WMI doesn't provide good per-process network info
            # This would require using Win32_PerfFormattedData_Tcpip_NetworkInterface
            # or falling back to netstat/psutil

            if self.verbose:
                print(f"[WMI] Network connection enumeration not fully supported via WMI")

        except Exception as e:
            if self.verbose:
                print(f"[WMI] Error getting network connections: {e}")

        return connections

    def get_process_modules(self, pid: int) -> List[Dict]:
        """
        Get loaded modules (DLLs) for a specific process

        Args:
            pid: Process ID

        Returns:
            List of module dictionaries
        """
        if not self.wmi_connection:
            return []

        modules = []

        try:
            # Query CIM_ProcessExecutable to get loaded modules
            query = f"SELECT * FROM CIM_ProcessExecutable WHERE Dependent = 'Win32_Process.Handle=\"{pid}\"'"

            for item in self.wmi_connection.query(query):
                if item.Antecedent:
                    # Parse the Antecedent to extract file path
                    # Format: Win32_DataFile.Name="C:\\path\\to\\file.dll"
                    module_path = item.Antecedent.split('Name="')[-1].rstrip('"')

                    modules.append({
                        "path": module_path,
                        "name": module_path.split("\\")[-1] if "\\" in module_path else module_path
                    })

            if self.verbose:
                print(f"[WMI] Found {len(modules)} modules for PID {pid}")

            return modules

        except Exception as e:
            if self.verbose:
                print(f"[WMI] Error getting process modules: {e}")
            return []

    def terminate_process(self, pid: int) -> bool:
        """
        Terminate a process via WMI

        Args:
            pid: Process ID

        Returns:
            True if successful, False otherwise
        """
        if not self.wmi_connection:
            return False

        try:
            processes = self.wmi_connection.Win32_Process(ProcessId=pid)

            if not processes:
                if self.verbose:
                    print(f"[WMI] Process {pid} not found for termination")
                return False

            result = processes[0].Terminate()

            if result == 0:
                if self.verbose:
                    print(f"[WMI] Successfully terminated PID {pid}")
                return True
            else:
                if self.verbose:
                    print(f"[WMI] Failed to terminate PID {pid}, result code: {result}")
                return False

        except Exception as e:
            if self.verbose:
                print(f"[WMI] Error terminating process {pid}: {e}")
            return False

    def _parse_wmi_datetime(self, wmi_datetime: str) -> str:
        """
        Parse WMI datetime format to ISO format

        Args:
            wmi_datetime: WMI datetime string (format: YYYYMMDDHHMMss.ffffff+TZD)

        Returns:
            ISO formatted datetime string
        """
        try:
            # WMI datetime format: YYYYMMDDHHMMss.ffffff+TZD
            # Example: 20231215143022.500000-480

            if not wmi_datetime:
                return None

            # Extract components
            year = int(wmi_datetime[0:4])
            month = int(wmi_datetime[4:6])
            day = int(wmi_datetime[6:8])
            hour = int(wmi_datetime[8:10])
            minute = int(wmi_datetime[10:12])
            second = int(wmi_datetime[12:14])

            dt = datetime(year, month, day, hour, minute, second)
            return dt.isoformat()

        except Exception as e:
            if self.verbose:
                print(f"[WMI] Error parsing datetime '{wmi_datetime}': {e}")
            return None

    def is_process_running(self, pid: int) -> bool:
        """
        Check if a process is currently running

        Args:
            pid: Process ID

        Returns:
            True if running, False otherwise
        """
        if not self.wmi_connection:
            return False

        try:
            processes = self.wmi_connection.Win32_Process(ProcessId=pid)
            return len(processes) > 0
        except Exception:
            return False

    def get_process_by_name(self, name: str) -> List[Dict]:
        """
        Get all processes with a specific name

        Args:
            name: Process name (e.g., "notepad.exe")

        Returns:
            List of process info dictionaries
        """
        if not self.wmi_connection:
            return []

        processes = []

        try:
            for process in self.wmi_connection.Win32_Process(Name=name):
                proc_info = self.get_process_info(process.ProcessId)
                if proc_info:
                    processes.append(proc_info)

            if self.verbose:
                print(f"[WMI] Found {len(processes)} processes with name '{name}'")

            return processes

        except Exception as e:
            if self.verbose:
                print(f"[WMI] Error finding processes by name '{name}': {e}")
            return []


# Testing function
def test_wmi_process_info():
    """Test the WMI process info retriever"""
    if not IS_WINDOWS:
        print("WMI is only available on Windows")
        return

    if not WMI_AVAILABLE:
        print("WMI module not installed. Install with: pip install wmi")
        return

    print("Testing WMI Process Info Retrieval")
    print("=" * 80)

    try:
        wmi_info = WMIProcessInfo(verbose=True)

        # Get current process info
        import os
        current_pid = os.getpid()

        print(f"\nTesting with current process PID {current_pid}:")
        print("-" * 80)

        info = wmi_info.get_process_info(current_pid)

        if info:
            print("\nProcess Information:")
            for key, value in info.items():
                print(f"  {key}: {value}")
        else:
            print("Failed to retrieve process info")

        # Test getting all processes
        print("\n" + "=" * 80)
        print("Getting all processes (first 10):")
        print("-" * 80)

        all_procs = wmi_info.get_all_processes()
        for proc in all_procs[:10]:
            print(f"  PID {proc['pid']}: {proc['name']}")

        print(f"\nTotal processes: {len(all_procs)}")

        # Test finding system processes
        print("\n" + "=" * 80)
        print("Testing access to system processes:")
        print("-" * 80)

        system_procs = wmi_info.get_process_by_name("System")
        for proc in system_procs:
            print(f"\nSystem Process Info:")
            for key, value in proc.items():
                print(f"  {key}: {value}")

    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_wmi_process_info()
