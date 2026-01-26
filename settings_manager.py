"""
Settings Manager - Handles application configuration for commercial release
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class SettingsManager:
    """Manager for application settings and configuration"""

    DEFAULT_SETTINGS = {
        "application": {
            "version": "1.0.0",
            "theme": "dark",
            "auto_refresh_interval": 2000,  # milliseconds
            "max_popups_per_rule": 3,
        },
        "paths": {
            "case_storage": "",  # Empty means auto-detect
            "yara_rules": "",    # Empty means auto-detect
            "whitelist": "",     # Empty means auto-detect
        },
        "api_keys": {
            "virustotal": "",
            "threathq_user": "",
            "threathq_pass": "",
        },
        "analysis": {
            "enable_process_monitoring": True,
            "enable_network_monitoring": True,
            "enable_yara_scanning": True,
            "auto_scan_new_processes": True,
            "enable_realtime_alerts": True,
        },
        "yara": {
            "create_backups_on_delete": True,
            "create_backups_on_update": True,
            "backup_directory": "_backups",
        },
        "case_management": {
            "auto_save_interval": 30,  # seconds
            "max_recent_cases": 10,
            "case_id_format": "CASE-%Y%m%d%H%M%S",
        },
        "ui": {
            "show_welcome_screen": True,
            "confirm_before_delete": True,
            "enable_tooltips": True,
        },
        "export": {
            "default_export_format": "json",
            "include_metadata": True,
            "include_hashes": True,
        },
        "security": {
            "require_admin_for_monitoring": True,
            "sanitize_paths_in_reports": False,
        },
        "advanced": {
            "debug_mode": False,
            "log_file": "mad.log",
            "max_log_size_mb": 50,
        }
    }

    def __init__(self, settings_file: Optional[str] = None):
        """
        Initialize the Settings Manager

        Args:
            settings_file: Path to settings file. If None, uses default location.
        """
        if settings_file is None:
            # Default location: same directory as the script
            settings_file = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "mad_settings.json"
            )

        self.settings_file = Path(settings_file)
        self.settings = self.DEFAULT_SETTINGS.copy()
        self.load_settings()

    def load_settings(self) -> bool:
        """
        Load settings from file

        Returns:
            True if loaded successfully, False otherwise
        """
        if not self.settings_file.exists():
            # Create default settings file
            self.save_settings()
            return True

        try:
            with open(self.settings_file, 'r', encoding='utf-8') as f:
                loaded_settings = json.load(f)

            # Merge with defaults to ensure all keys exist
            self.settings = self._merge_settings(self.DEFAULT_SETTINGS, loaded_settings)
            return True
        except Exception as e:
            print(f"Error loading settings: {e}")
            return False

    def save_settings(self) -> bool:
        """
        Save current settings to file

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Add metadata
            settings_with_meta = {
                "_metadata": {
                    "last_modified": datetime.now().isoformat(),
                    "version": self.settings["application"]["version"]
                },
                **self.settings
            }

            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(settings_with_meta, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a setting value using dot notation

        Args:
            key_path: Path to setting using dots (e.g., "api_keys.virustotal")
            default: Default value if key not found

        Returns:
            Setting value or default
        """
        keys = key_path.split('.')
        value = self.settings

        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key_path: str, value: Any) -> bool:
        """
        Set a setting value using dot notation

        Args:
            key_path: Path to setting using dots (e.g., "api_keys.virustotal")
            value: Value to set

        Returns:
            True if set successfully, False otherwise
        """
        keys = key_path.split('.')
        settings = self.settings

        try:
            # Navigate to the parent dictionary
            for key in keys[:-1]:
                if key not in settings:
                    settings[key] = {}
                settings = settings[key]

            # Set the value
            settings[keys[-1]] = value
            return True
        except Exception as e:
            print(f"Error setting value: {e}")
            return False

    def reset_to_defaults(self) -> bool:
        """
        Reset all settings to default values

        Returns:
            True if reset successfully, False otherwise
        """
        self.settings = self.DEFAULT_SETTINGS.copy()
        return self.save_settings()

    def reset_section(self, section: str) -> bool:
        """
        Reset a specific section to default values

        Args:
            section: Name of the section to reset (e.g., "api_keys")

        Returns:
            True if reset successfully, False otherwise
        """
        if section in self.DEFAULT_SETTINGS:
            self.settings[section] = self.DEFAULT_SETTINGS[section].copy()
            return self.save_settings()
        return False

    def export_settings(self, export_path: str) -> bool:
        """
        Export settings to a file

        Args:
            export_path: Path to export file

        Returns:
            True if exported successfully, False otherwise
        """
        try:
            import shutil
            shutil.copy2(self.settings_file, export_path)
            return True
        except Exception as e:
            print(f"Error exporting settings: {e}")
            return False

    def import_settings(self, import_path: str) -> bool:
        """
        Import settings from a file

        Args:
            import_path: Path to import file

        Returns:
            True if imported successfully, False otherwise
        """
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_settings = json.load(f)

            # Remove metadata if present
            imported_settings.pop('_metadata', None)

            # Merge with defaults
            self.settings = self._merge_settings(self.DEFAULT_SETTINGS, imported_settings)
            return self.save_settings()
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False

    def get_all_settings(self) -> Dict[str, Any]:
        """
        Get all settings

        Returns:
            Dictionary of all settings
        """
        return self.settings.copy()

    def _merge_settings(self, defaults: Dict, loaded: Dict) -> Dict:
        """
        Recursively merge loaded settings with defaults

        Args:
            defaults: Default settings dictionary
            loaded: Loaded settings dictionary

        Returns:
            Merged dictionary
        """
        result = defaults.copy()

        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_settings(result[key], value)
            else:
                result[key] = value

        return result

    def validate_api_keys(self) -> Dict[str, bool]:
        """
        Check if API keys are configured

        Returns:
            Dictionary with validation status for each API key
        """
        return {
            "virustotal": bool(self.get("api_keys.virustotal")),
            "threathq": bool(self.get("api_keys.threathq_user") and
                           self.get("api_keys.threathq_pass"))
        }

    def get_setting_description(self, key_path: str) -> str:
        """
        Get human-readable description for a setting

        Args:
            key_path: Path to setting using dots

        Returns:
            Description string
        """
        descriptions = {
            "application.version": "Application version number",
            "application.theme": "UI color theme (dark/light)",
            "application.auto_refresh_interval": "Auto-refresh interval in milliseconds",
            "application.max_popups_per_rule": "Maximum alert popups per YARA rule",
            "paths.case_storage": "Directory for storing case files",
            "paths.yara_rules": "Directory containing YARA rules (YDAMN)",
            "paths.whitelist": "Path to whitelist file",
            "api_keys.virustotal": "VirusTotal API key",
            "api_keys.threathq_user": "ThreatHQ username",
            "api_keys.threathq_pass": "ThreatHQ password",
            "analysis.enable_process_monitoring": "Enable real-time process monitoring",
            "analysis.enable_network_monitoring": "Enable network connection monitoring",
            "analysis.enable_yara_scanning": "Enable YARA rule scanning",
            "analysis.auto_scan_new_processes": "Automatically scan new processes with YARA",
            "analysis.enable_realtime_alerts": "Show real-time threat alerts",
            "yara.create_backups_on_delete": "Create backup when deleting YARA rules",
            "yara.create_backups_on_update": "Create backup when updating YARA rules",
            "yara.backup_directory": "Directory name for YARA rule backups",
            "case_management.auto_save_interval": "Auto-save interval in seconds",
            "case_management.max_recent_cases": "Maximum number of recent cases to show",
            "case_management.case_id_format": "Format string for case IDs",
            "ui.show_welcome_screen": "Show welcome screen on startup",
            "ui.confirm_before_delete": "Ask for confirmation before deleting",
            "ui.enable_tooltips": "Show helpful tooltips",
            "export.default_export_format": "Default format for exports (json/csv)",
            "export.include_metadata": "Include metadata in exports",
            "export.include_hashes": "Include file hashes in exports",
            "security.require_admin_for_monitoring": "Require admin privileges for monitoring",
            "security.sanitize_paths_in_reports": "Remove sensitive paths from reports",
            "advanced.debug_mode": "Enable debug logging",
            "advanced.log_file": "Log file name",
            "advanced.max_log_size_mb": "Maximum log file size in MB",
        }
        return descriptions.get(key_path, "No description available")
