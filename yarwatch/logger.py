
import os
import json
from datetime import datetime
from .config import log_file_path, json_log_path
import shutil

class YarLogger:
    def __init__(self, gui_queue=None):
        self.gui_queue = gui_queue

    def log(self, message):
        full_message = message
        if not self.gui_queue:
            print(full_message)  # ✅ Only print if not being handled by GUI

        # Log to GUI
        if self.gui_queue:
            self.gui_queue.put(full_message)

        # Log to text file
        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(full_message + "\n")

    def log_json(self, data, json_path="YarWatch_Log.json"):
        try:
            if os.path.exists(json_log_path):
                with open(json_log_path, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
            else:
                existing = []

            existing.append(data)

            with open(json_log_path, 'w', encoding='utf-8') as f:
                json.dump(existing, f, indent=2)

            # ✅ Push to GUI queue so collapsible frame shows up
            if self.gui_queue:
                self.gui_queue.put(data)

            return json_path

        except Exception as e:
            self.log(f"[ERROR] Failed to write to JSON log: {e}")

    def set_gui_queue(self, queue):
        self.gui_queue = queue
