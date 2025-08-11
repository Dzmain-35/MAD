import hashlib
import os
import re

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def is_pe_file(file_path):
    return file_path.lower().endswith(('.exe', '.dll'))

def extract_strings_from_binary(binary_data, min_len=5, max_len=50):
    pattern = re.compile(rb"[ -~]{%d,%d}" % (min_len, max_len))
    results = []
    matches = pattern.findall(binary_data)
    for match in matches:
        try:
            decoded = match.decode("utf-8", errors="ignore").strip()
            results.append(decoded[:max_len])
        except Exception:
            continue
    return results
