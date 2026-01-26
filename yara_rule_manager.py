"""
YARA Rule Manager - Handles validation, adding, and deleting YARA rules
"""

import os
import yara
from pathlib import Path
from typing import Tuple, List, Dict
import shutil
from datetime import datetime


class YaraRuleManager:
    """Manager for YARA rules with validation and file operations"""

    def __init__(self, yara_rules_path: str, settings_manager=None):
        """
        Initialize the YARA Rule Manager

        Args:
            yara_rules_path: Path to the YDAMN directory containing YARA rules
            settings_manager: Optional SettingsManager instance for network sync
        """
        self.yara_rules_path = Path(yara_rules_path)
        self.settings_manager = settings_manager

    def _sync_rule_to_network(self, rule_name: str, rule_content: str) -> Tuple[bool, str]:
        """
        Sync a YARA rule to the network folder

        Args:
            rule_name: Name of the rule file
            rule_content: Content of the rule

        Returns:
            Tuple of (success, message)
        """
        if not self.settings_manager:
            return True, ""  # No settings manager, skip silently

        if not self.settings_manager.get("network.enable_network_yara_sync", False):
            return True, ""  # Network sync disabled, skip silently

        network_path = self.settings_manager.get("network.network_yara_path", "")
        if not network_path:
            return True, ""  # No network path configured, skip silently

        try:
            import os
            # Ensure network directory exists
            os.makedirs(network_path, exist_ok=True)

            # Ensure rule name has extension
            if not rule_name.endswith('.yara') and not rule_name.endswith('.yar'):
                rule_name += '.yara'

            # Write rule to network path
            network_rule_path = os.path.join(network_path, rule_name)
            with open(network_rule_path, 'w', encoding='utf-8') as f:
                f.write(rule_content)

            return True, f"Synced to network: {network_rule_path}"

        except Exception as e:
            return False, f"Network sync failed: {str(e)}"

    def validate_yara_rule(self, rule_content: str) -> Tuple[bool, str]:
        """
        Validate YARA rule syntax before adding to the collection

        Args:
            rule_content: String containing YARA rule content

        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if rule is valid, False otherwise
            - error_message: Empty string if valid, error description if invalid
        """
        if not rule_content or not rule_content.strip():
            return False, "Rule content is empty"

        try:
            # Try to compile the rule to check for syntax errors
            yara.compile(source=rule_content)
            return True, ""
        except yara.SyntaxError as e:
            return False, f"YARA Syntax Error: {str(e)}"
        except Exception as e:
            return False, f"Validation Error: {str(e)}"

    def validate_yara_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Validate YARA rule file before adding to the collection

        Args:
            file_path: Path to YARA rule file

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_content = f.read()
            return self.validate_yara_rule(rule_content)
        except Exception as e:
            return False, f"Error reading file: {str(e)}"

    def add_rule_from_content(self, rule_name: str, rule_content: str) -> Tuple[bool, str]:
        """
        Add a new YARA rule from content string

        Args:
            rule_name: Name for the rule file (without extension)
            rule_content: YARA rule content as string

        Returns:
            Tuple of (success, message)
        """
        # Validate rule first
        is_valid, error_msg = self.validate_yara_rule(rule_content)
        if not is_valid:
            return False, f"Rule validation failed: {error_msg}"

        # Ensure rule name has .yara extension
        if not rule_name.endswith('.yara') and not rule_name.endswith('.yar'):
            rule_name += '.yara'

        # Create full path
        rule_path = self.yara_rules_path / rule_name

        # Check if file already exists
        if rule_path.exists():
            return False, f"Rule file '{rule_name}' already exists"

        try:
            # Ensure YDAMN directory exists
            self.yara_rules_path.mkdir(parents=True, exist_ok=True)

            # Write rule to file
            with open(rule_path, 'w', encoding='utf-8') as f:
                f.write(rule_content)

            # Sync to network if enabled
            network_success, network_msg = self._sync_rule_to_network(rule_name, rule_content)

            if network_success and network_msg:
                return True, f"Successfully added rule '{rule_name}'. {network_msg}"
            elif not network_success:
                return True, f"Successfully added rule '{rule_name}' (Warning: {network_msg})"

            return True, f"Successfully added rule '{rule_name}'"
        except Exception as e:
            return False, f"Error writing rule file: {str(e)}"

    def add_rule_from_file(self, source_file_path: str) -> Tuple[bool, str]:
        """
        Add a YARA rule from an external file

        Args:
            source_file_path: Path to the source YARA rule file

        Returns:
            Tuple of (success, message)
        """
        # Validate the file first
        is_valid, error_msg = self.validate_yara_file(source_file_path)
        if not is_valid:
            return False, f"Rule validation failed: {error_msg}"

        try:
            source_path = Path(source_file_path)
            dest_path = self.yara_rules_path / source_path.name

            # Check if file already exists
            if dest_path.exists():
                return False, f"Rule file '{source_path.name}' already exists"

            # Ensure YDAMN directory exists
            self.yara_rules_path.mkdir(parents=True, exist_ok=True)

            # Copy the file
            shutil.copy2(source_file_path, dest_path)

            return True, f"Successfully added rule '{source_path.name}'"
        except Exception as e:
            return False, f"Error copying rule file: {str(e)}"

    def delete_rule(self, rule_name: str, create_backup: bool = True) -> Tuple[bool, str]:
        """
        Delete a YARA rule file

        Args:
            rule_name: Name of the rule file to delete
            create_backup: If True, creates a backup before deletion

        Returns:
            Tuple of (success, message)
        """
        rule_path = self.yara_rules_path / rule_name

        if not rule_path.exists():
            return False, f"Rule file '{rule_name}' not found"

        try:
            # Create backup if requested
            if create_backup:
                backup_dir = self.yara_rules_path / "_backups"
                backup_dir.mkdir(exist_ok=True)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"{rule_path.stem}_{timestamp}{rule_path.suffix}"
                backup_path = backup_dir / backup_name

                shutil.copy2(rule_path, backup_path)

            # Delete the rule file
            rule_path.unlink()

            if create_backup:
                return True, f"Rule '{rule_name}' deleted (backup created)"
            else:
                return True, f"Rule '{rule_name}' deleted"
        except Exception as e:
            return False, f"Error deleting rule: {str(e)}"

    def list_rules(self) -> List[Dict[str, any]]:
        """
        List all YARA rules in the directory

        Returns:
            List of dictionaries containing rule information
        """
        if not self.yara_rules_path.exists():
            return []

        rules = []
        try:
            for rule_file in sorted(self.yara_rules_path.glob("*.yara")):
                rules.append({
                    "name": rule_file.name,
                    "path": str(rule_file),
                    "size": rule_file.stat().st_size,
                    "modified": datetime.fromtimestamp(rule_file.stat().st_mtime)
                })

            for rule_file in sorted(self.yara_rules_path.glob("*.yar")):
                rules.append({
                    "name": rule_file.name,
                    "path": str(rule_file),
                    "size": rule_file.stat().st_size,
                    "modified": datetime.fromtimestamp(rule_file.stat().st_mtime)
                })
        except Exception as e:
            print(f"Error listing rules: {e}")

        return rules

    def get_rule_content(self, rule_name: str) -> Tuple[bool, str]:
        """
        Get the content of a specific YARA rule

        Args:
            rule_name: Name of the rule file

        Returns:
            Tuple of (success, content/error_message)
        """
        rule_path = self.yara_rules_path / rule_name

        if not rule_path.exists():
            return False, f"Rule file '{rule_name}' not found"

        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return True, content
        except Exception as e:
            return False, f"Error reading rule: {str(e)}"

    def update_rule(self, rule_name: str, new_content: str, create_backup: bool = True) -> Tuple[bool, str]:
        """
        Update an existing YARA rule

        Args:
            rule_name: Name of the rule file to update
            new_content: New YARA rule content
            create_backup: If True, creates a backup before updating

        Returns:
            Tuple of (success, message)
        """
        rule_path = self.yara_rules_path / rule_name

        if not rule_path.exists():
            return False, f"Rule file '{rule_name}' not found"

        # Validate new content first
        is_valid, error_msg = self.validate_yara_rule(new_content)
        if not is_valid:
            return False, f"Rule validation failed: {error_msg}"

        try:
            # Create backup before updating if requested
            if create_backup:
                backup_dir = self.yara_rules_path / "_backups"
                backup_dir.mkdir(exist_ok=True)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"{rule_path.stem}_{timestamp}{rule_path.suffix}"
                backup_path = backup_dir / backup_name

                shutil.copy2(rule_path, backup_path)

            # Write new content
            with open(rule_path, 'w', encoding='utf-8') as f:
                f.write(new_content)

            # Sync to network if enabled
            network_success, network_msg = self._sync_rule_to_network(rule_name, new_content)

            backup_msg = " (backup created)" if create_backup else ""
            if network_success and network_msg:
                return True, f"Rule '{rule_name}' updated successfully{backup_msg}. {network_msg}"
            elif not network_success:
                return True, f"Rule '{rule_name}' updated successfully{backup_msg} (Warning: {network_msg})"

            return True, f"Rule '{rule_name}' updated successfully{backup_msg}"
        except Exception as e:
            return False, f"Error updating rule: {str(e)}"
