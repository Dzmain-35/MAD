# core/case_manager.py

import os
import json
from datetime import datetime

DATA_PATH = os.path.join("data", "cases.json")
os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
class CaseManager:
    def __init__(self):
        self.cases = self._load_cases()

    def _load_cases(self):
        if os.path.exists(DATA_PATH):
            with open(DATA_PATH, "r") as f:
                return json.load(f)
        return []

    def save_cases(self):
        with open(DATA_PATH, "w") as f:
            json.dump(self.cases, f, indent=4)

    def add_case(self, analyst, report_url, file_info):
        case = {
            "analyst": analyst,
            "report_url": report_url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "open",
            "files": [file_info]
        }

        self.cases.append(case)
        self.save_cases()
        return case

    def add_file_to_case(self, file_info):
        if not self.cases:
            print("[DEBUG] No active case to add file to.")
            return
        current_case = self.cases[-1]
        if "files" not in current_case:
            current_case["files"] = []
        current_case["files"].append(file_info)
        self.save_cases()
        print(f"[DEBUG] File added to case: {file_info['file_name']}")


    def get_all_cases(self):
        return self.cases

    def delete_case(self, index):
        if 0 <= index < len(self.cases):
            del self.cases[index]
            self.save_cases()
