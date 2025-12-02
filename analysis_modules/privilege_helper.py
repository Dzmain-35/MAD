"""
Windows Privilege Helper
Provides utilities for enabling process privileges like SeDebugPrivilege
This allows better access to system processes without full admin elevation
"""

import platform
from typing import Optional, List

# Check if running on Windows and import Windows-specific modules
IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes
else:
    ctypes = None
    wintypes = None

# Windows API Constants
if IS_WINDOWS:
    SE_PRIVILEGE_ENABLED = 0x00000002
    SE_PRIVILEGE_REMOVED = 0x00000004
    TOKEN_ADJUST_PRIVILEGES = 0x00000020
    TOKEN_QUERY = 0x00000008


if IS_WINDOWS:
    class LUID(ctypes.Structure):
        _fields_ = [
            ("LowPart", wintypes.DWORD),
            ("HighPart", wintypes.LONG),
        ]


    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Luid", LUID),
            ("Attributes", wintypes.DWORD),
        ]


    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]


class PrivilegeHelper:
    """
    Helper class for managing Windows process privileges
    """

    # Common privilege names
    SE_DEBUG_PRIVILEGE = "SeDebugPrivilege"
    SE_BACKUP_PRIVILEGE = "SeBackupPrivilege"
    SE_RESTORE_PRIVILEGE = "SeRestorePrivilege"
    SE_SHUTDOWN_PRIVILEGE = "SeShutdownPrivilege"
    SE_LOAD_DRIVER_PRIVILEGE = "SeLoadDriverPrivilege"
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE = "SeSystemEnvironmentPrivilege"
    SE_TAKE_OWNERSHIP_PRIVILEGE = "SeTakeOwnershipPrivilege"

    def __init__(self, verbose: bool = False):
        """
        Initialize the privilege helper

        Args:
            verbose: Enable verbose logging
        """
        if not IS_WINDOWS:
            raise RuntimeError("PrivilegeHelper requires Windows platform")

        self.verbose = verbose
        self.enabled_privileges = []

        if self.verbose:
            print(f"[PrivilegeHelper] Initialized on {platform.system()}")

    def enable_privilege(self, privilege_name: str) -> bool:
        """
        Enable a specific privilege for the current process

        Args:
            privilege_name: Name of the privilege (e.g., "SeDebugPrivilege")

        Returns:
            True if privilege was enabled successfully, False otherwise
        """
        try:
            # Get current process handle
            h_process = ctypes.windll.kernel32.GetCurrentProcess()

            # Open process token
            h_token = wintypes.HANDLE()
            if not ctypes.windll.advapi32.OpenProcessToken(
                h_process,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(h_token)
            ):
                error_code = ctypes.windll.kernel32.GetLastError()
                if self.verbose:
                    print(f"[PrivilegeHelper] Failed to open process token: Error {error_code}")
                return False

            try:
                # Lookup privilege value
                luid = LUID()
                if not ctypes.windll.advapi32.LookupPrivilegeValueW(
                    None,  # Local system
                    privilege_name,
                    ctypes.byref(luid)
                ):
                    error_code = ctypes.windll.kernel32.GetLastError()
                    if self.verbose:
                        print(f"[PrivilegeHelper] Failed to lookup privilege '{privilege_name}': Error {error_code}")
                    return False

                # Create TOKEN_PRIVILEGES structure
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

                # Adjust token privileges
                if not ctypes.windll.advapi32.AdjustTokenPrivileges(
                    h_token,
                    False,  # Don't disable all
                    ctypes.byref(tp),
                    ctypes.sizeof(tp),
                    None,  # Previous state not needed
                    None   # Return length not needed
                ):
                    error_code = ctypes.windll.kernel32.GetLastError()
                    if self.verbose:
                        print(f"[PrivilegeHelper] Failed to adjust token privileges: Error {error_code}")
                    return False

                # Check if privilege was actually enabled
                error_code = ctypes.windll.kernel32.GetLastError()
                if error_code == 0:  # ERROR_SUCCESS
                    if self.verbose:
                        print(f"[PrivilegeHelper] Successfully enabled '{privilege_name}'")
                    self.enabled_privileges.append(privilege_name)
                    return True
                elif error_code == 1300:  # ERROR_NOT_ALL_ASSIGNED
                    if self.verbose:
                        print(f"[PrivilegeHelper] Privilege '{privilege_name}' not held by user account")
                    return False
                else:
                    if self.verbose:
                        print(f"[PrivilegeHelper] Unexpected error code: {error_code}")
                    return False

            finally:
                # Close token handle
                ctypes.windll.kernel32.CloseHandle(h_token)

        except Exception as e:
            if self.verbose:
                print(f"[PrivilegeHelper] Exception enabling privilege '{privilege_name}': {e}")
                import traceback
                traceback.print_exc()
            return False

    def enable_debug_privilege(self) -> bool:
        """
        Enable SeDebugPrivilege for the current process
        This allows reading memory of other processes, including system processes

        Returns:
            True if privilege was enabled successfully, False otherwise
        """
        return self.enable_privilege(self.SE_DEBUG_PRIVILEGE)

    def disable_privilege(self, privilege_name: str) -> bool:
        """
        Disable a specific privilege for the current process

        Args:
            privilege_name: Name of the privilege (e.g., "SeDebugPrivilege")

        Returns:
            True if privilege was disabled successfully, False otherwise
        """
        try:
            # Get current process handle
            h_process = ctypes.windll.kernel32.GetCurrentProcess()

            # Open process token
            h_token = wintypes.HANDLE()
            if not ctypes.windll.advapi32.OpenProcessToken(
                h_process,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(h_token)
            ):
                if self.verbose:
                    print(f"[PrivilegeHelper] Failed to open process token")
                return False

            try:
                # Lookup privilege value
                luid = LUID()
                if not ctypes.windll.advapi32.LookupPrivilegeValueW(
                    None,
                    privilege_name,
                    ctypes.byref(luid)
                ):
                    if self.verbose:
                        print(f"[PrivilegeHelper] Failed to lookup privilege '{privilege_name}'")
                    return False

                # Create TOKEN_PRIVILEGES structure with privilege disabled
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = 0  # Disabled

                # Adjust token privileges
                if not ctypes.windll.advapi32.AdjustTokenPrivileges(
                    h_token,
                    False,
                    ctypes.byref(tp),
                    ctypes.sizeof(tp),
                    None,
                    None
                ):
                    if self.verbose:
                        print(f"[PrivilegeHelper] Failed to adjust token privileges")
                    return False

                if self.verbose:
                    print(f"[PrivilegeHelper] Successfully disabled '{privilege_name}'")

                if privilege_name in self.enabled_privileges:
                    self.enabled_privileges.remove(privilege_name)

                return True

            finally:
                ctypes.windll.kernel32.CloseHandle(h_token)

        except Exception as e:
            if self.verbose:
                print(f"[PrivilegeHelper] Exception disabling privilege '{privilege_name}': {e}")
            return False

    def check_privilege(self, privilege_name: str) -> Optional[bool]:
        """
        Check if a specific privilege is currently enabled

        Args:
            privilege_name: Name of the privilege to check

        Returns:
            True if enabled, False if disabled, None if error
        """
        try:
            # Get current process handle
            h_process = ctypes.windll.kernel32.GetCurrentProcess()

            # Open process token
            h_token = wintypes.HANDLE()
            if not ctypes.windll.advapi32.OpenProcessToken(
                h_process,
                TOKEN_QUERY,
                ctypes.byref(h_token)
            ):
                if self.verbose:
                    print(f"[PrivilegeHelper] Failed to open process token")
                return None

            try:
                # Lookup privilege value
                luid = LUID()
                if not ctypes.windll.advapi32.LookupPrivilegeValueW(
                    None,
                    privilege_name,
                    ctypes.byref(luid)
                ):
                    if self.verbose:
                        print(f"[PrivilegeHelper] Failed to lookup privilege '{privilege_name}'")
                    return None

                # Check privilege
                privilege_set = ctypes.c_int()
                if not ctypes.windll.advapi32.PrivilegeCheck(
                    h_token,
                    ctypes.byref(tp),
                    ctypes.byref(privilege_set)
                ):
                    if self.verbose:
                        print(f"[PrivilegeHelper] PrivilegeCheck failed")
                    return None

                return bool(privilege_set.value)

            finally:
                ctypes.windll.kernel32.CloseHandle(h_token)

        except Exception as e:
            if self.verbose:
                print(f"[PrivilegeHelper] Exception checking privilege '{privilege_name}': {e}")
            return None

    def get_enabled_privileges(self) -> List[str]:
        """
        Get list of privileges enabled by this helper

        Returns:
            List of privilege names that were successfully enabled
        """
        return self.enabled_privileges.copy()

    def is_elevated(self) -> bool:
        """
        Check if the current process is running with elevated privileges (admin)

        Returns:
            True if elevated, False otherwise
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def enable_common_privileges(self) -> dict:
        """
        Attempt to enable common debugging/analysis privileges

        Returns:
            Dictionary mapping privilege names to success status
        """
        privileges = [
            self.SE_DEBUG_PRIVILEGE,
            self.SE_BACKUP_PRIVILEGE,
            self.SE_RESTORE_PRIVILEGE,
        ]

        results = {}
        for priv in privileges:
            results[priv] = self.enable_privilege(priv)

        return results


# Convenience function
def enable_debug_privilege(verbose: bool = False) -> bool:
    """
    Convenience function to enable SeDebugPrivilege

    Args:
        verbose: Enable verbose logging

    Returns:
        True if successful, False otherwise
    """
    if not IS_WINDOWS:
        if verbose:
            print("[PrivilegeHelper] Not running on Windows, skipping privilege elevation")
        return False

    try:
        helper = PrivilegeHelper(verbose=verbose)
        return helper.enable_debug_privilege()
    except Exception as e:
        if verbose:
            print(f"[PrivilegeHelper] Failed to enable debug privilege: {e}")
        return False


def is_admin() -> bool:
    """
    Check if current process is running as administrator

    Returns:
        True if admin, False otherwise
    """
    if not IS_WINDOWS:
        return False

    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# Testing function
def test_privilege_helper():
    """Test the privilege helper"""
    if not IS_WINDOWS:
        print("Privilege helper is only available on Windows")
        return

    print("Testing Windows Privilege Helper")
    print("=" * 80)

    helper = PrivilegeHelper(verbose=True)

    print("\nChecking if running as administrator:")
    print(f"  Is Admin: {helper.is_elevated()}")

    print("\n" + "=" * 80)
    print("Attempting to enable SeDebugPrivilege:")
    print("-" * 80)

    success = helper.enable_debug_privilege()

    if success:
        print("\n✓ SeDebugPrivilege enabled successfully!")
        print("  This process now has enhanced access to other processes")
    else:
        print("\n✗ Failed to enable SeDebugPrivilege")
        print("  Possible reasons:")
        print("    - User account doesn't have SeDebugPrivilege")
        print("    - Running without administrator rights")
        print("    - Group policy restrictions")

    print("\n" + "=" * 80)
    print("Attempting to enable common privileges:")
    print("-" * 80)

    results = helper.enable_common_privileges()

    for priv, status in results.items():
        status_icon = "✓" if status else "✗"
        print(f"  {status_icon} {priv}: {'Enabled' if status else 'Failed'}")

    print("\n" + "=" * 80)
    print("Summary:")
    print("-" * 80)
    print(f"  Enabled privileges: {helper.get_enabled_privileges()}")

    if not helper.get_enabled_privileges():
        print("\n  Note: If no privileges were enabled, try running as administrator")
        print("  or ensure your user account has the required privileges assigned")


if __name__ == "__main__":
    test_privilege_helper()
