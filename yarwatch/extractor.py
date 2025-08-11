import os
import json
import pefile
import re
import subprocess
from datetime import datetime
from yarwatch.utils import calculate_md5, calculate_sha256, extract_strings_from_binary


class FeatureExtractor:
    def __init__(self, mal_data_path, max_len=40):
        self.mal_data_path = mal_data_path
        self.max_len = max_len

    def ensure_rule_directory(self, rule_name):
        rule_directory = os.path.join(self.mal_data_path, rule_name)
        os.makedirs(rule_directory, exist_ok=True)
        return rule_directory

    def save_strings(self, rule_name, strings):
        rule_dir = self.ensure_rule_directory(rule_name)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        file_path = os.path.join(rule_dir, f"strings_{timestamp}.txt")

        with open(file_path, 'w', encoding='utf-8') as f:
            for s in strings:
                if isinstance(s, bytes):
                    try:
                        s = s.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                s = s.strip()[:self.max_len]
                f.write(s + "\n")

    def save_hashes(self, rule_name, file_path):
        rule_dir = self.ensure_rule_directory(rule_name)
        hash_file = os.path.join(rule_dir, "hashes.txt")

        md5 = calculate_md5(file_path)
        sha256 = calculate_sha256(file_path)
        imphash = self.calculate_imphash(file_path)

        with open(hash_file, 'a') as f:
            f.write(f"MD5: {md5}\nSHA256: {sha256}\nIMPHASH: {imphash}\n\n")

    def calculate_imphash(self, file_path):
        try:
            pe = pefile.PE(file_path)
            return pe.get_imphash()
        except Exception:
            return "N/A"

    def extract_strings_from_file(self, file_path, min_len=6):
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return extract_strings_from_binary(data, min_len, self.max_len)
        except Exception as e:
            print(f"[ERROR] extracting strings from file: {e}")
            return []

    def extract_strings_from_pid(self, pid, delete_dump=True, matched_rule=None, logger=None):
        desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
        strings_dir = os.path.join(desktop_dir, "PID_Strings")
        os.makedirs(strings_dir, exist_ok=True)

        dump_file = os.path.join(desktop_dir, f"Memory_{pid}.dmp")
        output_file = os.path.join(strings_dir, f"pid_{pid}_strings.txt")

        try:
            if logger:
                logger.log(f"[INFO] Dumping memory from PID {pid}...")

            subprocess.run(f'procdump -mp -nobanner {pid} {dump_file}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            with open(dump_file, "rb") as f:
                data = f.read()

            strings = extract_strings_from_binary(data, 5, self.max_len)

            with open(output_file, "w", encoding="utf-8") as out_file:
                for s in strings:
                    out_file.write(s + "\n")

            if logger:
                logger.log(f"[INFO] Saved {len(strings)} strings to {output_file}")

            if matched_rule:
                self.save_strings(matched_rule, strings)
                if logger:
                    logger.log(f"[INFO] Saved extracted strings to mal_data_dir under rule: {matched_rule}")

            if delete_dump and os.path.exists(dump_file):
                os.remove(dump_file)

            return strings

        except Exception as e:
            if logger:
                logger.log(f"[ERROR] PID {pid} string extraction failed: {e}")
            return []



    def save_jsonl(self, rule_name, strings):
        rule_dir = self.ensure_rule_directory(rule_name)
        jsonl_path = os.path.join(rule_dir, "strings.jsonl")
        with open(jsonl_path, "a", encoding="utf-8") as f:
            for s in strings:
                f.write(json.dumps({"string": s}) + "\n")

    def save_csv(self, rule_name, strings):
        rule_dir = self.ensure_rule_directory(rule_name)
        csv_path = os.path.join(rule_dir, "strings.csv")
        with open(csv_path, "a", encoding="utf-8") as f:
            for s in strings:
                f.write(f"{s}\n")

class IMPHashScanner:
    def __init__(self, target_file, directory_to_scan):
        self.target_file = target_file
        self.directory_to_scan = directory_to_scan
        self.target_imphash = self.calculate_imphash()

    def calculate_imphash(self):
        try:
            pe = pefile.PE(self.target_file)
            return pe.get_imphash()
        except Exception:
            return None

    def scan_directory(self):
        if not self.target_imphash:
            return set()

        matching = set()
        for root, _, files in os.walk(self.directory_to_scan):
            if '1impHashes.txt' in files:
                path = os.path.join(root, '1impHashes.txt')
                with open(path, 'r') as f:
                    stored = f.read().strip()
                    if stored == self.target_imphash:
                        matching.add(os.path.basename(root))
        return matching

    def print_matches(self):
        matches = self.scan_directory()
        if matches:
            print(f"Found matches: {matches}")
        else:
            print("No matching folders found.")
