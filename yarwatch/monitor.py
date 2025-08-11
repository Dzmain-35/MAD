import psutil
import time
import threading
import concurrent.futures
from datetime import datetime
from yarwatch.config import disallowed_processes
from yarwatch.scanner import run_yara_pid

SCAN_COOLDOWN_SECONDS = 30  # Skip scanning a PID if scanned within last 30 sec

class Monitor:
    def __init__(self, logger, feature_extractor, gui):
        self.logger = logger
        self.extractor = feature_extractor
        self.gui = gui
        self.running = False
        self.excluded_pids = set()
        self.recent_scans = {}  # PID -> last scan time
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=5)

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join()
        self.logger.log("\n[Monitor] Watch stopped.")

    def _monitor_loop(self):
        existing_pids = {p.pid for p in psutil.process_iter()}
        while self.running:
            time.sleep(2)
            current_pids = {p.pid for p in psutil.process_iter()}
            new_pids = current_pids - existing_pids

            for pid in new_pids:
                if pid in self.excluded_pids:
                    continue

                now = time.time()
                if pid in self.recent_scans and now - self.recent_scans[pid] < SCAN_COOLDOWN_SECONDS:
                    continue  # Skip PID recently scanned

                self.recent_scans[pid] = now

                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower()
                    if proc_name not in [e.lower() for e in disallowed_processes]:
                        self.logger.log(f"[Monitor] New process: {proc_name} (PID: {pid})")
                        # Submit to thread pool for async scan
                        self.thread_pool.submit(run_yara_pid, pid, self.gui, self.extractor, self.logger)
                except psutil.AccessDenied:
                    self.logger.log(f"[Monitor] Access Denied: PID {pid}")
                    self.excluded_pids.add(pid)
                except psutil.NoSuchProcess:
                    continue

            existing_pids = current_pids
