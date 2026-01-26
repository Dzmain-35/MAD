"""
Process Activity Monitor - Procmon-style per-PID activity (user-mode)

This is a lightweight, dependency-free approximation of Process Monitor
for a SINGLE process. It uses psutil polling to emit events for:

  - FILE:   changes in open file handles (open / close)
  - THREAD: thread creation and exit
  - NET:    per-process connections (connect / close / state change)

Events are pushed to a callback so the GUI can update a live table.

NOTE:
True Procmon-level detail (every read/write, registry key, etc.) requires
ETW / kernel drivers. This module intentionally stays user-mode only and
safe to ship with MAD; registry activity is left as a stub for future ETW
integration.
"""

import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Set

import psutil


class ProcessActivityMonitor:
    """
    Lightweight, user-mode approximation of Procmon-style activity
    for a single PID.

    Captures:
      - File: changes in open file handles (open/close)
      - Thread: thread creation/exit
      - Net: per-process connections (connect/close/state change)

    Emits events through a callback:

        callback(event: Dict[str, Any])

    Event schema:
        {
          "timestamp": datetime,
          "pid": int,
          "process_name": str,
          "event_type": "FILE" | "THREAD" | "NET" | "PROCESS",
          "operation": str,
          "path": str | None,
          "details": str,
          "extra": dict   # type-specific fields
        }

    Registry ("REG") is left as a stub for future ETW/Sysmon integration.
    """

    def __init__(
        self,
        pid: int,
        callback: Callable[[Dict[str, Any]], None],
        poll_interval: float = 0.5,
    ) -> None:
        self.pid = pid
        self.callback = callback
        self.poll_interval = poll_interval

        self._thread: Optional[threading.Thread] = None
        self._running = False

        self._proc: Optional[psutil.Process] = None
        self._process_name: str = ""

        # snapshots (previous state)
        self._open_files: Set[str] = set()
        self._threads: Set[int] = set()
        self._conns: Dict[str, str] = {}  # conn_id -> status

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        """Start monitoring the process in a background thread."""
        if self._running:
            return False

        try:
            self._proc = psutil.Process(self.pid)
            self._process_name = self._proc.name()
        except psutil.NoSuchProcess:
            return False

        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout: Optional[float] = 1.0) -> None:
        """Stop monitoring and join the thread."""
        if not self._running:
            return
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #

    def _emit(self, event: Dict[str, Any]) -> None:
        """Safely emit an event to the callback."""
        try:
            self.callback(event)
        except Exception:
            # GUI callback errors should not kill the monitor thread
            pass

    def _loop(self) -> None:
        assert self._proc is not None
        first = True

        while self._running:
            try:
                if not self._proc.is_running():
                    self._emit(
                        {
                            "timestamp": datetime.utcnow(),
                            "pid": self.pid,
                            "process_name": self._process_name,
                            "event_type": "PROCESS",
                            "operation": "Exit",
                            "path": None,
                            "details": "Process terminated",
                            "extra": {},
                        }
                    )
                    self._running = False
                    break

                self._poll_files(initial=first)
                self._poll_threads(initial=first)
                self._poll_net(initial=first)
                # self._poll_registry(initial=first)  # stub for future ETW/Sysmon

                first = False

            except psutil.NoSuchProcess:
                self._running = False
                break
            except Exception:
                # never crash the thread on unexpected errors
                pass

            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------ #
    # FILE HANDLES
    # ------------------------------------------------------------------ #

    def _poll_files(self, initial: bool) -> None:
        try:
            open_files = self._proc.open_files()  # type: ignore[union-attr]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return
        except Exception:
            return

        current_paths: Set[str] = set()
        for of in open_files:
            path = of.path or ""
            if not path:
                continue
            current_paths.add(path)

            # newly opened
            if path not in self._open_files and not initial:
                self._emit(
                    {
                        "timestamp": datetime.utcnow(),
                        "pid": self.pid,
                        "process_name": self._process_name,
                        "event_type": "FILE",
                        "operation": "Open",
                        "path": path,
                        "details": "File handle opened",
                        "extra": {},
                    }
                )

        if not initial:
            # handles that disappeared (closed)
            for path in self._open_files - current_paths:
                self._emit(
                    {
                        "timestamp": datetime.utcnow(),
                        "pid": self.pid,
                        "process_name": self._process_name,
                        "event_type": "FILE",
                        "operation": "Close",
                        "path": path,
                        "details": "File handle closed",
                        "extra": {},
                    }
                )

        self._open_files = current_paths

    # ------------------------------------------------------------------ #
    # THREADS
    # ------------------------------------------------------------------ #

    def _poll_threads(self, initial: bool) -> None:
        try:
            threads = self._proc.threads()  # type: ignore[union-attr]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return
        except Exception:
            return

        current_tids: Set[int] = set()
        for t in threads:
            tid = t.id
            current_tids.add(tid)
            if tid not in self._threads and not initial:
                self._emit(
                    {
                        "timestamp": datetime.utcnow(),
                        "pid": self.pid,
                        "process_name": self._process_name,
                        "event_type": "THREAD",
                        "operation": "Start",
                        "path": None,
                            "details": f"Thread {tid} started",
                        "extra": {
                            "tid": tid,
                            "user_time": t.user_time,
                            "system_time": t.system_time,
                        },
                    }
                )

        if not initial:
            for tid in self._threads - current_tids:
                self._emit(
                    {
                        "timestamp": datetime.utcnow(),
                        "pid": self.pid,
                        "process_name": self._process_name,
                        "event_type": "THREAD",
                        "operation": "Exit",
                        "path": None,
                        "details": f"Thread {tid} exited",
                        "extra": {"tid": tid},
                    }
                )

        self._threads = current_tids

    # ------------------------------------------------------------------ #
    # NETWORK
    # ------------------------------------------------------------------ #

    def _make_conn_id(self, c: psutil._common.sconn) -> str:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "0.0.0.0:0"
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "0.0.0.0:0"
        return f"{c.fd}-{c.type}-{laddr}->{raddr}"

    def _poll_net(self, initial: bool) -> None:
        try:
            conns = self._proc.connections(kind="inet")  # type: ignore[union-attr]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return
        except Exception:
            return

        current: Dict[str, str] = {}
        for c in conns:
            cid = self._make_conn_id(c)
            status = c.status
            current[cid] = status

            if cid not in self._conns and not initial:
                self._emit(
                    {
                        "timestamp": datetime.utcnow(),
                        "pid": self.pid,
                        "process_name": self._process_name,
                        "event_type": "NET",
                        "operation": "Connect",
                        "path": None,
                        "details": f"{status} {cid}",
                        "extra": {
                            "status": status,
                            "laddr": c.laddr,
                            "raddr": c.raddr,
                            "fd": c.fd,
                        },
                    }
                )
            elif cid in self._conns and self._conns[cid] != status and not initial:
                self._emit(
                    {
                        "timestamp": datetime.utcnow(),
                        "pid": self.pid,
                        "process_name": self._process_name,
                        "event_type": "NET",
                        "operation": "StateChange",
                        "path": None,
                        "details": f"{self._conns[cid]} -> {status} {cid}",
                        "extra": {
                            "old_status": self._conns[cid],
                            "status": status,
                            "laddr": c.laddr,
                            "raddr": c.raddr,
                            "fd": c.fd,
                        },
                    }
                )

        if not initial:
            for cid in set(self._conns.keys()) - set(current.keys()):
                self._emit(
                    {
                        "timestamp": datetime.utcnow(),
                        "pid": self.pid,
                        "process_name": self._process_name,
                        "event_type": "NET",
                        "operation": "Close",
                        "path": None,
                        "details": f"Connection closed {cid}",
                        "extra": {},
                    }
                )

        self._conns = current

    # ------------------------------------------------------------------ #
    # REGISTRY (stub for future ETW/Sysmon integration)
    # ------------------------------------------------------------------ #

    def _poll_registry(self, initial: bool) -> None:
        # Placeholder for future work:
        #  - hook Microsoft-Windows-Kernel-Registry ETW provider
        #  - or tail Sysmon event logs and filter on PID
        # For now this is intentionally a no-op to keep this module
        # dependency-free and safe to run anywhere.
        return
