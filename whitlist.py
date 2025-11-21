import os
import hashlib

# Directories to scan
PROGRAM_DIRS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)"
]

OUTPUT_FILE = "whitelist.txt"


def sha256_file(path):
    """Return SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Could not hash {path}: {e}")
        return None


def scan_and_append_hashes():
    """Walk directories and append SHA256 hashes to whitelist.txt."""
    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        for directory in PROGRAM_DIRS:
            if not os.path.exists(directory):
                continue

            print(f"[*] Scanning {directory} ...")
            for root, _, files in os.walk(directory):
                for file in files:
                    full_path = os.path.join(root, file)

                    # Only hash executables and libraries
                    if not file.lower().endswith((".exe", ".dll", ".sys", ".ocx")):
                        continue

                    sha256 = sha256_file(full_path)
                    if sha256:
                        out.write(f"{sha256}  {full_path}\n")
                        print(f"[+] {sha256}  {full_path}")

    print(f"\nDone! Hashes appended to {OUTPUT_FILE}")


if __name__ == "__main__":
    scan_and_append_hashes()
