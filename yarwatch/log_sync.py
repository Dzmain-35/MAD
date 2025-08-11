import os
import shutil
from datetime import datetime

def get_desktop_log_path(filename="YarWatch_Log.json"):
    """Returns the full path to the JSON file on the Desktop."""
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    return os.path.join(desktop, filename)

def copy_json_to_shared_folder(source_path, shared_base_path):
    """Copies the given JSON log to a date-organized folder in the shared path."""
    if not os.path.exists(source_path):
        print(f"[ERROR] JSON file does not exist: {source_path}")
        return

    today = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%H-%M-%S")

    target_dir = os.path.join(shared_base_path, today)
    os.makedirs(target_dir, exist_ok=True)

    dest_filename = f"scan_{timestamp}.json"
    dest_path = os.path.join(target_dir, dest_filename)

    try:
        shutil.copy(source_path, dest_path)
        print(f"[LOG] JSON copied to: {dest_path}")
    except Exception as e:
        print(f"[ERROR] Failed to copy JSON to shared folder: {e}")
