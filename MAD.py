import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import datetime
import json
import hashlib
import threading
import psutil
import shutil
import queue
import time
import re
import ctypes
import ctypes.wintypes as wt
from itertools import chain
from tkinter import ttk
from core.case_manager import CaseManager
from core.traffic import TrafficPanel, TrafficTwoPane
from yarwatch.dns_extractor_memory import DNSExtractor
from yarwatch.extractor import FeatureExtractor
from yarwatch.logger import YarLogger
from yarwatch.scanner import run_yara_file, run_yara_pid
from yarwatch.monitor import Monitor
from yarwatch.collapsible_frame import CollapsibleScanFrame 
from yarwatch.yarwatch_panel import YarWatchPanel
from PIL import Image

# ========== CONFIG ==========
destination_path = "C:/Users/REM/Desktop/Case Data"  # where a copy of uploads is stored

disallowed_processes = [
    "dllhost.exe", "py.exe", "chrome.exe", "python.exe",
    "procdump64.exe", "procdump.exe", "updater.exe", "wscript.exe",
    "powershell.exe", "cmd.exe", "SearchProtocolHost.exe",
    "searchfilterhost.exe", "backgroundTaskHost.exe", "ipconfig.exe", "ConEmuC.exe",
]

safe_windows_processes = [
    "SearchUI.exe", "explorer.exe", "RuntimeBroker.exe",
    "vmtoolsd.exe", "python.exe", "msfeedssync.exe",
    "wmic.exe", "ielowutil.exe",
]

# ---------- Risk color helpers ----------
def get_score_color(level):
    return {
        "Critical": "#cc0000",
        "High": "#ff6600",
        "Medium": "#ffcc00",
        "Low": "#00cc66"
    }.get(level, "#4a5568")

def get_threat_color(level):
    return {
        "Critical": "#990000",
        "High": "#cc5200",
        "Medium": "#b38f00",
        "Low": "#0d6b3a"
    }.get(level, "#00334d")

def readable_on(bg_hex):
    bg_hex = bg_hex.lstrip("#")
    r, g, b = int(bg_hex[0:2],16), int(bg_hex[2:4],16), int(bg_hex[4:6],16)
    yiq = ((r*299)+(g*587)+(b*114))/1000
    return "black" if yiq > 180 else "white"

def _safe_call(fn, default="—"):
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess, ProcessLookupError):
        return default
    except Exception:
        return default

def _fmt_ts(ts):
    try:
        import datetime as _dt
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "—"
def _extract_ascii_strings(data: bytes, minlen: int):
    out, run = [], []
    for b in data:
        if 32 <= b <= 126:  # printable ASCII
            run.append(b)
        else:
            if len(run) >= minlen:
                out.append(bytes(run).decode('ascii', 'ignore'))
            run.clear()
    if len(run) >= minlen:
        out.append(bytes(run).decode('ascii', 'ignore'))
    return out

def _extract_utf16le_strings(data: bytes, minlen: int):
    out, run = [], bytearray()
    i, n = 0, len(data)
    # look for pattern: printable byte followed by 0x00
    while i + 1 < n:
        b0, b1 = data[i], data[i+1]
        if 32 <= b0 <= 126 and b1 == 0x00:
            run += bytes([b0, b1])
            i += 2
        else:
            if len(run) // 2 >= minlen:
                try:
                    out.append(run.decode('utf-16le'))
                except Exception:
                    pass
            run.clear()
            i += 2 if b1 == 0 else 1
    if len(run) // 2 >= minlen:
        try:
            out.append(run.decode('utf-16le'))
        except Exception:
            pass
    return out

# add this tiny helper somewhere near UploadedFileRow
class _NullRow:
    def __getattr__(self, _):  # any method becomes a no-op
        def _noop(*a, **k): 
            pass
        return _noop

# ========== Row UI for uploads with color-by-risk ==========
class UploadedFileRow(ctk.CTkFrame):
    def __init__(self, master, filename, sha256, stored_path=None, on_delete=None, **kwargs):
        super().__init__(master, **kwargs)
        self.filename = filename
        self.sha256 = sha256
        self.stored_path = stored_path
        self.on_delete = on_delete

        self.configure(fg_color="#0E2536", corner_radius=10, border_width=0)
        self.columnconfigure(0, weight=1)

        self.name_lbl = ctk.CTkLabel(self, text=filename, anchor="w", font=("Arial", 14, "bold"))
        self.name_lbl.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))

        self.status_lbl = ctk.CTkLabel(self, text="Queued…", anchor="w", text_color="#cbd5e1")
        self.status_lbl.grid(row=1, column=0, sticky="ew", padx=10)

        self.pb = ctk.CTkProgressBar(self)
        self.pb.set(0.0)
        self.pb.grid(row=2, column=0, sticky="ew", padx=10, pady=(4, 10))

        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.grid(row=0, column=1, rowspan=3, sticky="ns", padx=(8, 10), pady=8)

        self.delete_btn = ctk.CTkButton(
            self.btn_frame, text="Delete", width=80, command=self._confirm_delete,
            fg_color="#8b0000", hover_color="#a40000"
        )
        self.delete_btn.pack(fill="x", pady=(10, 4))

        self._risk_level = None
        self._risk_score = None
    
    def set_status(self, text: str):
        self.status_lbl.configure(text=text)

    def set_progress(self, value: float):
        self.pb.configure(mode="determinate")
        self.pb.set(max(0.0, min(1.0, value)))

    def start_indeterminate(self):
        self.pb.configure(mode="indeterminate")
        self.pb.start()

    def stop_indeterminate(self):
        try:
            self.pb.stop()
        except Exception:
            pass
        self.pb.configure(mode="determinate")

    def mark_done(self, ok=True):
        self.stop_indeterminate()
        self.set_progress(1.0 if ok else 0.0)
        self.status_lbl.configure(
            text=("Completed" if ok else "Failed"),
            text_color=("#34a853" if ok else "#ea4335")
        )

    def apply_risk_style(self, level: str, score: int | float = None):
        self._risk_level = level
        self._risk_score = score
        border = get_score_color(level)
        self.configure(border_color=border, border_width=2)
        self.status_lbl.configure(text_color=readable_on(border))
        if score is not None:
            self.status_lbl.configure(text=f"{level} risk — score {score}")

    def _confirm_delete(self):
        msg = "Remove this file from the case?\n\nYou can also delete the stored copy next."
        if not messagebox.askyesno("Remove from case", msg):
            return
        delete_disk = messagebox.askyesno("Delete stored copy?", "Also delete the stored copy from disk (if present)?")
        if self.on_delete:
            ok = self.on_delete(self.sha256, self.stored_path if delete_disk else None)
        else:
            ok = True
        if ok:
            self.destroy()

# ========== Collapsible UI with risk-aware header ==========
class CollapsibleFrame(ctk.CTkFrame):
    def __init__(self, master, title="Details", content=[], risk_level=None, **kwargs):
        super().__init__(master, **kwargs)
        self.columnconfigure(0, weight=1)
        self.expanded = False
        header_color = get_threat_color(risk_level) if risk_level else "#004080"
        text_color = readable_on(header_color)

        self.header = ctk.CTkButton(self, text=title, command=self.toggle,
                                    fg_color=header_color, text_color=text_color,
                                    font=("Arial", 20, "bold"))
        self.header.grid(row=0, column=0, sticky="ew", padx=5, pady=2)

        self.content_frame = ctk.CTkFrame(self, fg_color="#102A3C")

        formatted = "\n".join(content)
        self.textbox = ctk.CTkTextbox(
            self.content_frame,
            wrap="word",
            font=("Consolas", 15),
            text_color="white",
            fg_color="#102A3C"
        )
        self.textbox.insert("1.0", formatted)
        self.textbox.configure(state="normal")
        self.textbox.pack(fill="both", expand=True, padx=10, pady=5)

    def toggle(self):
        if self.expanded:
            self.content_frame.grid_forget()
        else:
            self.content_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=(0, 5))
        self.expanded = not self.expanded

class ProcessPanel(ctk.CTkFrame):
    REFRESH_MS = 700  

    def __init__(self, master, dashboard, **kwargs):
        super().__init__(master, fg_color="#0E2536", **kwargs)
        self.dashboard = dashboard
        self._watch = tk.BooleanVar(value=True)       # live by default
        self._hide_safe = tk.BooleanVar(value=False)
        self._filter_text = tk.StringVar(value="")
        self._building = False                        # model-build guard
        self._tree_items = {}                         # pid -> iid
        self._last_procs = {}                         # pid -> record (for diffing)
        self._live_job = None

        self._build_ui()
        self._start_live()
    def _build_ui(self):
        # Toolbar
        tb = ctk.CTkFrame(self, fg_color="#0B1F2C")
        tb.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(tb, text="Processes", font=("Arial", 20, "bold")).pack(side="left", padx=(8, 6))

        self.filter_entry = ctk.CTkEntry(
            tb, placeholder_text="filter by name or PID…",
            textvariable=self._filter_text, width=220
        )
        self.filter_entry.pack(side="left", padx=6)
        self.filter_entry.bind("<KeyRelease>", lambda e: self._refresh_now())

        self.hide_safe_chk = ctk.CTkCheckBox(
            tb, text="Hide safe Windows",
            variable=self._hide_safe, command=self._refresh_now
        )
        self.hide_safe_chk.pack(side="left", padx=10)

        # optional "refresh now" button (useful when paused)
        self.refresh_btn = ctk.CTkButton(tb, text="Refresh now", width=110, command=self._refresh_now)
        self.refresh_btn.pack(side="right", padx=6)

        # live switch (LIVE unless paused)
        self.watch_btn = ctk.CTkSwitch(tb, text="Live (pause to stop)", variable=self._watch, command=self._on_watch_toggled)
        self.watch_btn.pack(side="right", padx=(6, 12))

        # Treeview
        tv_wrap = ctk.CTkFrame(self, fg_color="#0E2536")
        tv_wrap.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        cols = ("Name", "PID", "PPID", "User", "CPU%", "Mem(MB)", "Path", "Started")
        self.tree = ttk.Treeview(tv_wrap, columns=cols, show="tree headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("#0", width=24, stretch=False)  # tree indicator
        self.tree.column("Name", width=240, anchor="w")
        self.tree.column("PID", width=70, anchor="e")
        self.tree.column("PPID", width=70, anchor="e")
        self.tree.column("User", width=160, anchor="w")
        self.tree.column("CPU%", width=70, anchor="e")
        self.tree.column("Mem(MB)", width=90, anchor="e")
        self.tree.column("Path", width=360, anchor="w")
        self.tree.column("Started", width=160, anchor="w")
        self.tree.pack(fill="both", expand=True)

        # Events
        self.tree.bind("<Double-1>", self._on_open_details)
        self.tree.bind("<Button-3>", self._on_context_menu)

        # Styles
        style = ttk.Style(self.tree)
        style.configure("Treeview", background="#0E2536", fieldbackground="#0E2536", foreground="white")
        style.map("Treeview", background=[("selected", "#1d4ed8")])
        self.tree.tag_configure("disallowed", background="#3b0f0f")
        self.tree.tag_configure("safe", background="#0f2a38")
    def _strings_pid(self, pid):
        try:
            StringsViewer(self, pid)
        except Exception as e:
            messagebox.showerror("Strings error", str(e))

    def _start_live(self):
        self._cancel_live_job()
        self._live_tick()

    def _stop_live(self):
        self._cancel_live_job()

    def _cancel_live_job(self):
        if self._live_job is not None:
            try:
                self.after_cancel(self._live_job)
            except Exception:
                pass
            self._live_job = None

    def _on_watch_toggled(self):
        if self._watch.get():
            self._start_live()
        else:
            self._stop_live()

    def _refresh_now(self):
        # one-shot immediate model rebuild & diff apply
        if not self._building:
            self._building = True
            threading.Thread(target=self._build_model_thread, daemon=True).start()

    def _live_tick(self):
        if self._watch.get():
            self._refresh_now()
            self._live_job = self.after(self.REFRESH_MS, self._live_tick)

    # ---------- Model build + incremental UI apply ----------
    def _build_model_thread(self):
        import datetime as _dt
        procs = {}
        by_ppid = {}
        filt = self._filter_text.get().strip().lower()
        hide_safe = self._hide_safe.get()

        for p in psutil.process_iter(attrs=["pid", "ppid", "name", "username", "exe", "create_time"]):
            try:
                pid = p.info["pid"]
                name = p.info.get("name") or ""
                if hide_safe and name in safe_windows_processes:
                    continue
                if filt and (filt not in name.lower()) and (filt not in str(pid)):
                    continue

                # Dynamic fields
                try:
                    cpu = p.cpu_percent(interval=None)
                except Exception:
                    cpu = 0.0
                try:
                    mem_mb = (p.memory_info().rss or 0) / (1024 * 1024)
                except Exception:
                    mem_mb = 0.0

                exe = p.info.get("exe") or ""
                user = p.info.get("username") or ""
                ppid = p.info.get("ppid") or 0
                try:
                    started = _dt.datetime.fromtimestamp(p.info.get("create_time", 0)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    started = ""

                rec = {
                    "pid": pid, "ppid": ppid, "name": name, "user": user,
                    "cpu": round(cpu, 1), "mem": round(mem_mb, 1),
                    "exe": exe, "started": started
                }
                procs[pid] = rec
                by_ppid.setdefault(ppid, []).append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        # Sort children for consistent placement
        for plist in by_ppid.values():
            plist.sort(key=lambda x: (procs[x]["name"].lower(), procs[x]["pid"]))

        self.after(0, lambda: self._apply_model_diffs(procs, by_ppid))

    def _apply_model_diffs(self, procs, by_ppid):
        """Incrementally update the tree without clearing it."""
        # Remember selection to restore if needed
        selected_pid = self._get_selected_pid()

        old = self._last_procs
        new = procs

        old_pids = set(old.keys())
        new_pids = set(new.keys())
        added = new_pids - old_pids
        removed = old_pids - new_pids
        common = new_pids & old_pids

        # Remove vanished PIDs
        for pid in removed:
            iid = self._tree_items.pop(pid, None)
            if iid and self.tree.exists(iid):
                try:
                    self.tree.delete(iid)
                except Exception:
                    pass

        # Add new PIDs (place under parent if known)
        def _parent_iid_for(pid):
            parent_pid = new[pid]["ppid"]
            if parent_pid in self._tree_items:
                return self._tree_items[parent_pid]
            return ""  # root

        for pid in sorted(added, key=lambda x: (new[x]["name"].lower(), new[x]["pid"])):
            r = new[pid]
            parent_iid = _parent_iid_for(pid)
            iid = self.tree.insert(parent_iid, "end", text="", values=(
                r["name"], r["pid"], r["ppid"], r["user"],
                r["cpu"], r["mem"], r["exe"], r["started"]
            ))
            self._tree_items[pid] = iid
            # Tags
            nm = r["name"]
            if nm in disallowed_processes:
                self.tree.item(iid, tags=("disallowed",))
            elif nm in safe_windows_processes:
                self.tree.item(iid, tags=("safe",))

        # Update existing PIDs (values and parent if changed)
        for pid in common:
            r_new = new[pid]
            r_old = old[pid]
            iid = self._tree_items.get(pid)
            if not iid or not self.tree.exists(iid):
                # was missing (edge case) -> re-create
                parent_iid = _parent_iid_for(pid)
                iid = self.tree.insert(parent_iid, "end", text="", values=(
                    r_new["name"], r_new["pid"], r_new["ppid"], r_new["user"],
                    r_new["cpu"], r_new["mem"], r_new["exe"], r_new["started"]
                ))
                self._tree_items[pid] = iid
            else:
                # Move if parent changed
                if r_new["ppid"] != r_old["ppid"]:
                    parent_iid = _parent_iid_for(pid)
                    try:
                        self.tree.move(iid, parent_iid, "end")
                    except Exception:
                        pass
                # Update values if changed
                if r_new != r_old:
                    self.tree.item(iid, values=(
                        r_new["name"], r_new["pid"], r_new["ppid"], r_new["user"],
                        r_new["cpu"], r_new["mem"], r_new["exe"], r_new["started"]
                    ))
                # Update tag if needed
                nm = r_new["name"]
                if nm in disallowed_processes:
                    self.tree.item(iid, tags=("disallowed",))
                elif nm in safe_windows_processes:
                    self.tree.item(iid, tags=("safe",))
                else:
                    self.tree.item(iid, tags=())

        # Save latest snapshot
        self._last_procs = new

        # Restore selection if still present
        if selected_pid in self._tree_items:
            try:
                self.tree.selection_set(self._tree_items[selected_pid])
            except Exception:
                pass

        self._building = False

    # ----- interactions -----
    def _get_selected_pid(self):
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        vals = self.tree.item(iid, "values")
        if not vals:
            return None
        try:
            return int(vals[1])  # PID column
        except Exception:
            return None

    def _on_open_details(self, event=None):
        pid = self._get_selected_pid()
        if pid is None:
            return
        ProcessDetails(self, self.dashboard, pid)

    def _on_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
        pid = self._get_selected_pid()
        if pid is None:
            return
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Open Details", command=lambda: ProcessDetails(self, self.dashboard, pid))
        menu.add_separator()
        menu.add_command(label="Scan PID", command=lambda: self._scan_pid(pid))
        menu.add_command(label="Strings", command=lambda: self._strings_pid(pid))

        menu.add_command(label="DNS/URLs", command=lambda: self._dns_pid(pid))
        menu.tk_popup(event.x_root, event.y_root)

    def _scan_pid(self, pid):
        try:
            name = psutil.Process(pid).name()
            if name in disallowed_processes:
                messagebox.showinfo("Not allowed", f"Scanning '{name}' (PID {pid}) is disabled by policy.")
                return
        except Exception:
            pass

        def worker():
            try:
                extractor = self.dashboard.analysis_feature_extractor
                logger = self.dashboard.analysis_logger
                run_yara_pid(pid, self.dashboard, extractor, logger)
                messagebox.showinfo("Scan complete", f"PID {pid} scan finished. Check Analysis → Console.")
            except Exception as e:
                messagebox.showerror("Scan failed", str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _dump_pid(self, pid):
        def worker():
            try:
                fx = self.dashboard.analysis_feature_extractor
                if hasattr(fx, "dump_pid"):
                    out = fx.dump_pid(pid)
                    messagebox.showinfo("Dump complete", f"Dumped PID {pid} to:\n{out}")
                else:
                    messagebox.showwarning("Not implemented", "FeatureExtractor.dump_pid not found.")
            except Exception as e:
                messagebox.showerror("Dump failed", str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _dns_pid(self, pid):
        def worker():
            try:
                extractor = DNSExtractor()
                try:
                    domains, removed, proc_info = extractor.extract_from_process(pid)
                except TypeError:
                    domains = extractor.extract_from_process(pid, include_children=False)
                    removed, proc_info = [], {}
                msg = "No domains found." if not domains else "\n".join(sorted(set(domains))[:100])
                messagebox.showinfo("DNS Extract", msg)
            except Exception as e:
                messagebox.showerror("DNS Extract failed", str(e))
        threading.Thread(target=worker, daemon=True).start()
# ========== Main App ==========
class MalwareDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("MAD - Malware Analysis Dashboard")
        self.geometry("1200x800")
        self.case_manager = CaseManager()
        self.nav_buttons = {}
        self.sections = {}
        self.analysis_tabview = None
        self.analysis_container = None
        self.active_tab = None
        self._ui_rows_by_sha = {}
        self._pid_header_printed = False  # for Analysis console compact header
        self.analysis_console = None       # set when Analysis tab is built
        self.analysis_output_queue = None
        self.analysis_logger = None
        self.analysis_feature_extractor = None
        self.analysis_monitor = None

        self.setup_sidebar()
        self.show_section("New Case") 

    # ---------- Sidebar & Navigation ----------
    def setup_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=200,fg_color="#A30000")
        sidebar.pack(side="left", fill="y")

        nav_items = ["New Case", "Current Case", "Analysis"]
        for item in nav_items:
            btn = ctk.CTkButton(sidebar, text=item, width=180, height=40, corner_radius=6,
                                fg_color="#0E2536", hover_color="#0d2d45", text_color="white",
                                command=lambda i=item: self.show_section(i))
            btn.pack(pady=10, padx=10)
            self.nav_buttons[item] = btn
    # put these inside your Dashboard / MalwareDashboard class

    def _format_file_details(self, file_info: dict) -> str:
        return (
            f"File Name: {file_info.get('file_name', 'N/A')}\n"
            f"MD5: {file_info.get('md5', 'N/A')}\n"
            f"SHA256: {file_info.get('sha256', 'N/A')}\n"
            f"File Size: {file_info.get('size', 'N/A')} bytes"
        )

    def _copy_case_file_details(self, file_info: dict):
        text = self._format_file_details(file_info)
        # use Tk clipboard (no extra deps)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()  # keep on clipboard after window loses focus

    # Convenience to append to the Analysis console from anywhere
    def _append_analysis_log(self, text: str):
        try:
            box = self.analysis_console
            if not box or not box.winfo_exists():
                return
            box.configure(state="normal")
            box.insert("end", text.rstrip("\n") + "\n")
            box.see("end")
            box.configure(state="disabled")
        except Exception:
            pass

    # 1) Put this on your GUI class (MalwareDashboard)
    def update_collapsible_output(self, results: dict):
        """
        Called by scanner.run_yara_pid/file() when a scan finishes.
        Writes compact row to Analysis console: FileName : PID : Rule
        """
        tgt_type = results.get("target_type")
        rule = results.get("rule") or "No_YARA_Hit"
        file_name = results.get("file_name") or results.get("process_name") or "Unknown"
        pid = results.get("target") if tgt_type == "pid" else "-"
        line = f"{file_name} : {pid} : {rule}"

        # Clear the old PHRem block and print our compact table header once per session
        if not self._pid_header_printed and self.analysis_console and self.analysis_console.winfo_exists():
            self.analysis_console.configure(state="normal")
            self.analysis_console.delete("1.0", "end")
            self.analysis_console.insert("end", "File Name : PID : Rule Match\n")
            self.analysis_console.insert("end", "─" * 60 + "\n")
            self.analysis_console.configure(state="disabled")
            self._pid_header_printed = True

        self._append_analysis_log(line)

    def show_section(self, section_name):
        self.clear_main_area()
        # reset the compact header when moving away/back to Analysis
        if section_name != "Analysis":
            self._pid_header_printed = False
        if section_name == "New Case":
            self.show_intro_tab()
        elif section_name == "Current Case":
            self.show_case_tab()
        elif section_name == "Analysis":
            self.show_analysis_tab()

    def clear_main_area(self):
        if self.active_tab:
            self.active_tab.pack_forget()
            self.active_tab = None

    # ---------- New Case ----------
    def show_intro_tab(self):
        self.clear_main_area()
        frame = ctk.CTkFrame(self, fg_color="#0E2536")
        frame.pack(fill="both", expand=True)
        self.active_tab = frame

        # Logo (optional)
        try:
            logo_img = ctk.CTkImage(Image.open("core/image.png"), size=(250, 250))
            logo_border = ctk.CTkFrame(frame, border_color="red", border_width=3, fg_color="black")
            logo_border.pack(pady=(30, 10))
            logo_label = ctk.CTkLabel(logo_border, image=logo_img, text="")
            logo_label.pack()
        except Exception:
            pass

        ctk.CTkLabel(frame, text="New Malware Case", font=("Arial", 45, "bold"), text_color="white").pack(pady=(30, 10))
        ctk.CTkFrame(frame, height=2, fg_color="#cc0000").pack(fill="x", padx=120, pady=(5, 20))

        self.analyst_entry = ctk.CTkEntry(frame, placeholder_text="Enter Analyst Name", width=350, fg_color="#A30000", text_color="white",font=("Arial", 20, "bold"))
        self.analyst_entry.pack(pady=10)
        self.report_entry = ctk.CTkEntry(frame, placeholder_text="Enter Report URL", width=350, fg_color="#A30000", text_color="white",font=("Arial", 20, "bold"))
        self.report_entry.pack(pady=10)

        ctk.CTkButton(frame, text="Upload File to Start Case", command=self.handle_file_upload,width=45,height=45, fg_color="#A30000",hover_color="#800000").pack(pady=(20, 10))

        self.uploads_panel = ctk.CTkScrollableFrame(frame, fg_color="#102A3C")
        self.uploads_panel.pack(fill="both", expand=True, padx=20, pady=(10, 10))

    # ---------- Current Case ----------
    def show_case_tab(self):
        self.clear_main_area()
        frame = ctk.CTkFrame(self, fg_color="#0E2536")
        frame.pack(fill="both", expand=True)
        self.active_tab = frame

        cases = self.case_manager.get_all_cases()
        if not cases:
            ctk.CTkLabel(frame, text="No case has been created yet.", text_color="white").pack(pady=20)
            return

        case = cases[-1]
        ctk.CTkLabel(frame, text="Current Case Details", font=("Arial", 25, "bold"), text_color="white").pack(pady=10)
        text_box = ctk.CTkTextbox(frame, wrap="word", height=120, font=("Consolas", 20), text_color="white", fg_color="#102A3C")
        core_info = f"Analyst: {case.get('analyst','')}\nReport URL: {case.get('report_url','')}\nTimestamp: {case.get('timestamp','')}\nStatus: {case.get('status','')}"
        text_box.insert("1.0", core_info)
        text_box.configure(state="disabled")
        text_box.pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(frame, text="Attached Files:", font=("Arial", 22, "bold"), text_color="white").pack(pady=(10, 5))
        file_panel = ctk.CTkScrollableFrame(frame, fg_color="#102A3C")
        file_panel.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        for f in case.get("files", []):
            container = ctk.CTkFrame(file_panel, fg_color="#0E2536", corner_radius=10,
                                     border_width=2, border_color=get_score_color(f.get("risk_level", "Low")))
            container.pack(fill="x", padx=6, pady=6)
            container.grid_columnconfigure(0, weight=1)

            lines = ["File Details:", "="*66, f"File Name: {f.get('file_name')}",
                     f"MD5: {f.get('md5', 'N/A')}", f"SHA256: {f.get('sha256', 'N/A')}",
                     f"File Size: {f.get('size', 'N/A')} bytes", "="*66,
                     f"IMPHASH: {f.get('imphash', 'N/A')}", f"YARA Rule: {f.get('rule', 'None')}",
                     f"VT Hits: {f.get('vt_hits', 0)}", f"THQ Family: {f.get('thq_family', 'None')}",
                     f"Threat Score: {f.get('threat_score', 0)} ({f.get('risk_level', 'Low')})", "="*66]
            if f.get("strings"):
                lines.append("YARA String Matches:")
                lines.extend([f"  - {s}" for s in f.get("strings", [])[:10]])
            rule_display = f.get("rule")
            if rule_display and rule_display != "None":
                header_title = f"{f.get('file_name', 'Unknown File')}  —  {rule_display}"
            else:
                header_title = f.get("file_name", "Unknown File")

            cf = CollapsibleFrame(container,
                      title=header_title,
                      content=lines,
                      risk_level=f.get("risk_level"))
            cf.grid(row=0, column=0, sticky="w", padx=5, pady=5)

            # after creating 'container'
            container.grid_columnconfigure(0, weight=1)  # content stretches
            container.grid_columnconfigure(1, weight=0)
            container.grid_columnconfigure(2, weight=0)

            cf.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

            # Delete button
            del_btn = ctk.CTkButton(
                container, text="Delete",
                fg_color="#8b0000", hover_color="#a40000", width=100,
                command=lambda sha=f.get("sha256"), name=f.get("file_name"): self._delete_file_from_case_ui(sha, name)
            )
            del_btn.grid(row=0, column=1, sticky="ns", padx=(6, 4), pady=6)

            # Copy details button
            copy_btn = ctk.CTkButton(
                container, text="Copy details", width=120,
                command=lambda fi=f: self._copy_case_file_details(fi)
            )
            copy_btn.grid(row=0, column=2, sticky="ns", padx=(4, 8), pady=6)

        ctk.CTkButton(frame, text="Attach File to Case",font=("Arial", 20, "bold"), command=self.attach_file_to_case, fg_color="#A30000").pack(pady=(5, 10))

    # ---------- Analysis Tab ----------
    def show_analysis_tab(self):
        if self.analysis_container and self.analysis_container.winfo_exists():
            self.analysis_container.pack(fill="both", expand=True, padx=10, pady=10)
            self.active_tab = self.analysis_container
            return

        # Wire logger to a queue the console will drain
        self.analysis_output_queue = queue.Queue()
        self.analysis_logger = YarLogger(gui_queue=self.analysis_output_queue)
        self.analysis_feature_extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
        self.analysis_monitor = Monitor(self.analysis_logger, self.analysis_feature_extractor, self)

        self.analysis_container = ctk.CTkFrame(self, fg_color="#0E2536")
        self.analysis_container.pack(fill="both", expand=True, padx=10, pady=10)
        self.active_tab = self.analysis_container

        self.analysis_tabview = ctk.CTkTabview(self.analysis_container, corner_radius=8,fg_color="#0E2536")
        self.analysis_tabview.pack(fill="both", expand=True)

        # --- Processes tab (live tree + console) ---
        if "YarWatch" not in self.analysis_tabview._tab_dict:
            yarwatch_tab = self.analysis_tabview.add("YarWatch")
            self.show_yarwatch_tab_embedded(yarwatch_tab)

        if "Processes" not in self.analysis_tabview._tab_dict:
            proc_tab = self.analysis_tabview.add("Process")
            proc_tab.grid_columnconfigure(0, weight=1)
            proc_tab.grid_rowconfigure(0, weight=1)
            proc_tab.grid_rowconfigure(1, weight=0)

            proc_panel = ProcessPanel(proc_tab, dashboard=self)
            proc_panel.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))

            console = ctk.CTkTextbox(proc_tab, height=160, wrap="none", font=("Consolas", 12), fg_color="#102A3C", text_color="white")
            console.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))
            console.insert("1.0", "[Console ready]\n")
            console.configure(state="disabled")
            self.analysis_console = console

            # start pumping log queue into console
            self.after(150, self._analysis_pump_logs)
    
        # Traffic tab
        if "Traffic" not in self.analysis_tabview._tab_dict:
            traffic_tab = self.analysis_tabview.add("Traffic")
            self._analysis_show_traffic(traffic_tab)

    def _analysis_pump_logs(self):
        """
        Pulls messages from YarLogger queue and prints them to the Analysis console.
        """
        try:
            if self.analysis_output_queue and not self.analysis_output_queue.empty():
                while True:
                    try:
                        msg = self.analysis_output_queue.get_nowait()
                    except queue.Empty:
                        break
                    self._append_analysis_log(str(msg))
        finally:
            # re-schedule pump
            if self.analysis_container and self.analysis_container.winfo_exists():
                self.after(200, self._analysis_pump_logs)

    def show_yarwatch_tab_embedded(self, parent_frame):
        output_queue = queue.Queue()
        logger = YarLogger(gui_queue=output_queue)
        extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
        monitor = Monitor(logger, extractor, self)
        yarwatch = YarWatchPanel(parent_frame, extractor, logger, output_queue, monitor, dashboard_gui=self)
        yarwatch.pack(fill="both", expand=True)

    def _analysis_show_traffic(self, parent):
        """Create the Traffic tab panel and wire actions."""
        panel = TrafficTwoPane(
            parent,
            on_scan_pid=lambda pid: run_yara_pid(
                pid,
                gui=self,
                feature_extractor=self.analysis_feature_extractor,
                logger=self.analysis_logger
            ),
            on_view_dns=self._analysis_view_dns_from_pid
        )
        panel.pack(fill="both", expand=True, padx=6, pady=6)
        self.traffic_panel = panel  # keep a reference if needed

    def _analysis_view_dns_from_pid(self, pid: int):
        """Run your DNS extractor against a PID and stream results to the Analysis output."""
        try:
            extractor = DNSExtractor()
            try:
                domains, removed, proc_info = extractor.extract_from_process(pid)
            except TypeError:
                domains = extractor.extract_from_process(pid, include_children=False)
                removed, proc_info = [], {}
            # Push to the Analysis console
            self._append_analysis_log(f"[DNS] PID {pid} domains ({len(domains)}):")
            if domains:
                for d in domains:
                    self._append_analysis_log(f"  - {d}")
            else:
                self._append_analysis_log("  (none)")

            if proc_info and proc_info.get("connections"):
                self._append_analysis_log(f"[NET] PID {pid} connections:")
                for c in proc_info["connections"]:
                    proto = c.get("protocol", "")
                    local = c.get("local", "")
                    remote = c.get("remote", "")
                    status = c.get("status", "")
                    self._append_analysis_log(f"  {proto} {local} -> {remote} ({status})")
        except Exception as e:
            self._append_analysis_log(f"[DNS] PID {pid} error: {e}")

    # ---------- Upload handlers ----------
    def handle_file_upload(self):
        analyst = getattr(self, "analyst_entry", None).get().strip() if hasattr(self, "analyst_entry") else ""
        report_url = getattr(self, "report_entry", None).get().strip() if hasattr(self, "report_entry") else ""
        if not analyst or not report_url:
            messagebox.showwarning("Missing Info", "Please fill in both fields before continuing.")
            return

        file_path = filedialog.askopenfilename(title="Select Malware Sample")
        if not file_path:
            return

        sha256 = self._calc_sha256(file_path)
        file_name = os.path.basename(file_path)
        stored_copy = os.path.join(destination_path, file_name)

        row = UploadedFileRow(self.uploads_panel, filename=file_name, sha256=sha256, stored_path=stored_copy, on_delete=self._handle_delete_file_from_row)
        row.pack(fill="x", padx=6, pady=6)
        self._ui_rows_by_sha[sha256] = row

        t = threading.Thread(target=self._process_new_case_upload, args=(file_path, analyst, report_url, sha256), daemon=True)
        t.start()

    def attach_file_to_case(self):
        file_path = filedialog.askopenfilename(title="Attach Additional File")
        if not file_path:
            return

        sha256 = self._calc_sha256(file_path)
        # de-dupe by sha256 against current case
        cases = self.case_manager.get_all_cases()
        if cases and any(f.get("sha256") == sha256 for f in cases[-1].get("files", [])):
            messagebox.showinfo("Already attached", "This file is already in the case.")
            return

        file_name = os.path.basename(file_path)
        stored_copy = os.path.join(destination_path, file_name)

        # only show a transient row if uploads_panel exists (New Case screen)
        parent = getattr(self, "uploads_panel", None)
        if parent and parent.winfo_exists():
            row = UploadedFileRow(parent, filename=file_name, sha256=sha256,
                                stored_path=stored_copy, on_delete=self._handle_delete_file_from_row)
            row.pack(fill="x", padx=6, pady=6)
        else:
            row = _NullRow()  # no visible row on Current Case screen

        self._ui_rows_by_sha[sha256] = row
        threading.Thread(target=self._process_attach_file, args=(file_path, sha256), daemon=True).start()


    # ---------- Processing threads ----------
    def _process_new_case_upload(self, file_path, analyst, report_url, sha256):
        row = self._ui_rows_by_sha.get(sha256)

        def ui(fn, *args, **kwargs):
            self.after(0, lambda: fn(*args, **kwargs))

        try:
            ui(row.set_status, "Copying to case store…")
            ui(row.set_progress, 0.1)
            os.makedirs(destination_path, exist_ok=True)
            dest_path = os.path.join(destination_path, os.path.basename(file_path))
            try:
                shutil.copy(file_path, dest_path)
            except Exception:
                pass
            ui(row.set_progress, 0.2)

            ui(row.set_status, "YARA scanning…")
            ui(row.start_indeterminate)
            extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
            logger = YarLogger(gui_queue=self.analysis_output_queue)  # also tee to console
            run_yara_file(file_path, self, self, extractor, logger)
            ui(row.stop_indeterminate)
            ui(row.set_progress, 0.8)

            ui(row.set_status, "Finalizing case…")
            last = self._read_last_yarwatch_entry()
            score = last.get("threat_score")
            level = last.get("risk_level")
            if level:
                ui(row.apply_risk_style, level, score)

            self.case_manager.add_case(analyst, report_url, last)
            # persist in case_manager if method exists
            if hasattr(self.case_manager, "save_cases"):
                self.case_manager.save_cases()

            ui(row.set_progress, 1.0)
            ui(row.mark_done, True)
            ui(lambda: messagebox.showinfo("Success", "Case successfully created and stored."))
            ui(self.show_case_tab)

        except Exception as e:
            ui(row.set_status, f"Error: {e}")
            ui(row.mark_done, False)

    def _process_attach_file(self, file_path, sha256):
        row = self._ui_rows_by_sha.get(sha256)

        def ui(fn, *args, **kwargs):
            self.after(0, lambda: fn(*args, **kwargs))

        try:
            ui(row.set_status, "Copying to case store…")
            ui(row.set_progress, 0.1)
            os.makedirs(destination_path, exist_ok=True)
            dest_path = os.path.join(destination_path, os.path.basename(file_path))
            try:
                shutil.copy(file_path, dest_path)
            except Exception:
                pass
            ui(row.set_progress, 0.2)

            ui(row.set_status, "YARA scanning…")
            ui(row.start_indeterminate)
            extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
            logger = YarLogger(gui_queue=self.analysis_output_queue)  # tee to console
            run_yara_file(file_path, self, self, extractor, logger)
            ui(row.stop_indeterminate)
            ui(row.set_progress, 0.85)

            ui(row.set_status, "Updating case…")
            last = self._read_last_yarwatch_entry()
            score = last.get("threat_score")
            level = last.get("risk_level")
            if level:
                ui(row.apply_risk_style, level, score)

            self.case_manager.add_file_to_case(last)
            if hasattr(self.case_manager, "save_cases"):
                self.case_manager.save_cases()

            ui(row.set_progress, 1.0)
            ui(row.mark_done, True)
            ui(lambda: messagebox.showinfo("Attached", "File successfully attached to case."))
            ui(self.show_case_tab)

        except Exception as e:
            ui(row.set_status, f"Error: {e}")
            ui(row.mark_done, False)

    # ---------- Delete logic ----------
    def _handle_delete_file_from_row(self, sha256, stored_path_to_delete=None) -> bool:
        try:
            removed = self._delete_file_from_case(sha256)
            if stored_path_to_delete and os.path.exists(stored_path_to_delete):
                try:
                    os.remove(stored_path_to_delete)
                except Exception as e:
                    messagebox.showwarning("Disk delete", f"File removed from case, but failed to delete from disk:\n{e}")
            self._ui_rows_by_sha.pop(sha256, None)
            if self.active_tab and hasattr(self.active_tab, "winfo_exists") and self.active_tab.winfo_exists():
                self.show_case_tab()
            return True
        except Exception as e:
            messagebox.showerror("Delete failed", str(e))
            return False

    def _delete_file_from_case_ui(self, sha256, file_name):
        if not sha256:
            messagebox.showwarning("Delete", "Missing SHA256 for file; cannot remove.")
            return
        if not messagebox.askyesno("Confirm Delete", f"Remove '{file_name}' from the current case?"):
            return

        stored = os.path.join(destination_path, file_name) if file_name else None
        try:
            removed = self._delete_file_from_case(sha256)
            if stored and os.path.exists(stored):
                try:
                    os.remove(stored)
                except Exception:
                    pass
            messagebox.showinfo("Deleted", f"Removed '{file_name}' from the case.")
            self.show_case_tab()
        except Exception as e:
            messagebox.showerror("Delete failed", str(e))

    def _delete_file_from_case(self, sha256) -> bool:
        cases = self.case_manager.get_all_cases()
        if not cases:
            return False
        case = cases[-1]
        files = case.get("files", [])
        new_files = [f for f in files if f.get("sha256") != sha256]
        changed = len(new_files) != len(files)
        if changed:
            case["files"] = new_files
            if hasattr(self.case_manager, "save_cases"):
                self.case_manager.save_cases()
            else:
                self.case_manager.cases = cases
        return changed

    # ---------- Helpers ----------
    def _calc_sha256(self, file_path):
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _read_last_yarwatch_entry(self):
        log_path = "C:\\Users\\REM\\Desktop\\YarWatch_Log.json"
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                entries = json.load(f)
            return entries[-1] if entries else {}
        except Exception:
            return {}

    def update_attached_files_panel(self):
        if self.active_tab and isinstance(self.active_tab, ctk.CTkFrame):
            self.show_section("Current Case")

class StringsViewer(ctk.CTkToplevel):
    """
    On-demand process-strings viewer with fast 'Quick mode' sampling,
    ASCII + UTF-16LE detection, search filtering, and Copy All.
    """
    def __init__(self, master, pid: int):
        super().__init__(master)
        self.title(f"Strings — PID {pid}")
        self.geometry("1050x800")
        self.pid = pid

        # ---- UI state
        self._min_len = tk.IntVar(value=7)
        self._quick   = tk.BooleanVar(value=True)  # fast sampled scan by default
        self._filter  = tk.StringVar(value="")
        self._all_strings: list[str] = []
        self._shown_strings: list[str] = []
        self._busy = False

        # ---- Layout
        outer = ctk.CTkFrame(self, fg_color="#0E2536")
        outer.pack(fill="both", expand=True, padx=10, pady=10)

        ctrl = ctk.CTkFrame(outer, fg_color="transparent")
        ctrl.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(ctrl, text="Min length:").pack(side="left", padx=(0, 6))
        ctk.CTkEntry(ctrl, textvariable=self._min_len, width=60).pack(side="left")

        ctk.CTkSwitch(ctrl, text="Quick mode", variable=self._quick).pack(side="left", padx=(12, 0))

        ctk.CTkLabel(ctrl, text="Search:").pack(side="left", padx=(12, 6))
        ctk.CTkEntry(ctrl, textvariable=self._filter, width=280, placeholder_text="type to filter (case-insensitive)")\
            .pack(side="left")
        ctk.CTkButton(ctrl, text="Apply", command=self._apply_filter).pack(side="left", padx=(6, 0))
        ctk.CTkButton(ctrl, text="Clear", command=self._clear_filter).pack(side="left", padx=(6, 0))

        ctk.CTkButton(ctrl, text="Refresh", command=self._extract_once).pack(side="right", padx=(6, 0))
        ctk.CTkButton(ctrl, text="Copy All", command=self._copy_all).pack(side="right")

        # output text
        self.text = ctk.CTkTextbox(outer, wrap="none", font=("Consolas", 12), fg_color="#102A3C", text_color="white")
        self.text.pack(fill="both", expand=True)
        self.text.insert("1.0", "Fetching strings…\n")
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.after(50,self._extract_once)

    # ---------- UI helpers

    def _append(self, line: str):
        """Thread-safe append to the textbox."""
        self.text.after(0, lambda: (
            self.text.insert("end", (line + ("\n" if not line.endswith("\n") else ""))),
            self.text.see("end")
        ))

    def _render(self, items: list[str]):
        self._shown_strings = items
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if not items:
            self.text.insert("1.0", "(no strings)")
        else:
            self.text.insert("1.0", "\n".join(items))
        self.text.configure(state="normal")
        self.text.see("end")

    def _copy_all(self):
        data = self.text.get("1.0", "end-1c")
        try:
            self.clipboard_clear()
            self.clipboard_append(data)
            self.update()
        except Exception:
            pass

    def _apply_filter(self):
        needle = (self._filter.get() or "").lower().strip()
        if not needle:
            self._render(self._all_strings)
            return
        self._render([s for s in self._all_strings if needle in s.lower()])

    def _clear_filter(self):
        self._filter.set("")
        self._render(self._all_strings)

    def _extract_once(self):
        if self._busy:
            return
        self._busy = True
        # disable button + set status
        try:
            self._refresh_btn.configure(state="disabled", text="Refreshing…")
        except Exception:
            pass
        threading.Thread(target=self._worker, daemon=True).start()
    @staticmethod

    def _extract_ascii_strings(data: bytes, minlen: int) -> list[str]:
        out, run = [], []
        for b in data:
            if 32 <= b <= 126:
                run.append(b)
            else:
                if len(run) >= minlen:
                    out.append(bytes(run).decode("ascii", "ignore"))
                run.clear()
        if len(run) >= minlen:
            out.append(bytes(run).decode("ascii", "ignore"))
        return out

    @staticmethod
    def _extract_utf16le_strings(data: bytes, minlen: int) -> list[str]:
        out, run = [], bytearray()
        i, n = 0, len(data)
        while i + 1 < n:
            b0, b1 = data[i], data[i + 1]
            if 32 <= b0 <= 126 and b1 == 0x00:
                run += bytes([b0, b1])
                i += 2
            else:
                if len(run) // 2 >= minlen:
                    try:
                        out.append(run.decode("utf-16le"))
                    except Exception:
                        pass
                run.clear()
                i += 2 if b1 == 0 else 1
        if len(run) // 2 >= minlen:
            try:
                out.append(run.decode("utf-16le"))
            except Exception:
                pass
        return out

    # ---------- core worker (Python 3.12-safe Win32)

    def _worker(self):
        # caps (Quick mode)
        QUICK_MAX_PER_REGION = 256 * 1024        # 256 KB per region
        QUICK_MAX_TOTAL      = 32 * 1024 * 1024  # 32 MB per run
        PAGE_READABLE = (
    0x02 |  # PAGE_READONLY
    0x04 |  # PAGE_READWRITE
    0x08 |  # PAGE_WRITECOPY
    0x20 |  # PAGE_EXECUTE_READ
    0x40 |  # PAGE_EXECUTE_READWRITE
    0x80    # PAGE_EXECUTE_WRITECOPY
)
        MEM_COMMIT   = 0x1000

        import ctypes, ctypes.wintypes as wt
        SIZE_T  = ctypes.c_size_t
        LPVOID  = ctypes.c_void_p
        LPCVOID = ctypes.c_void_p
        HANDLE  = wt.HANDLE

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)

        OpenProcess = k32.OpenProcess
        OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        OpenProcess.restype  = HANDLE

        ReadProcessMemory = k32.ReadProcessMemory
        ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
        ReadProcessMemory.restype  = wt.BOOL

        VirtualQueryEx = k32.VirtualQueryEx
        VirtualQueryEx.argtypes = [HANDLE, LPCVOID, ctypes.c_void_p, SIZE_T]
        VirtualQueryEx.restype  = SIZE_T

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress",       LPVOID),
                ("AllocationBase",    LPVOID),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize",        SIZE_T),
                ("State",             wt.DWORD),
                ("Protect",           wt.DWORD),
                ("Type",              wt.DWORD),
            ]

        try:
            minlen = max(2, int(self._min_len.get() or 4))
        except Exception:
            minlen = 4
            self._min_len.set(4)
        quick = bool(self._quick.get())

        hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        if not hProc:
            self._append(f"[!] OpenProcess failed for PID {self.pid}. Try running as admin.")
            return

        try:
            addr = 0
            mbi = MEMORY_BASIC_INFORMATION()
            total_read = 0
            seen = set()

            # collect into a list, then render once (faster UI)
            collected: list[str] = []

            while True:
                r = VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not r:
                    break

                base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
                size = int(mbi.RegionSize)
                prot = int(mbi.Protect)
                state = int(mbi.State)

                if state == MEM_COMMIT and (prot & PAGE_READABLE):
                    region_to_scan = min(size, QUICK_MAX_PER_REGION) if quick else size
                    CHUNK = 128 * 1024
                    off = 0

                    while off < region_to_scan:
                        to_read = min(CHUNK, region_to_scan - off)
                        buf = (ctypes.c_ubyte * to_read)()
                        nread = SIZE_T()
                        ok = ReadProcessMemory(hProc, ctypes.c_void_p(base + off), buf, SIZE_T(to_read), ctypes.byref(nread))
                        if ok and nread.value:
                            total_read += int(nread.value)
                            data = bytes(buf[: nread.value])

                            # skip very-low-entropy pages
                            if data and data.count(0) > len(data) * 0.90:
                                off += to_read
                                continue

                            # extract strings fast
                            for s in self._extract_ascii_strings(data, minlen):
                                if s not in seen:
                                    seen.add(s)
                                    collected.append(s)
                            for s in self._extract_utf16le_strings(data, minlen):
                                if s not in seen:
                                    seen.add(s)
                                    collected.append(s)

                            if quick and total_read >= QUICK_MAX_TOTAL:
                                self._append("[quick mode: byte cap reached]")
                                raise StopIteration
                        off += to_read

                addr = base + size

        except StopIteration:
            pass
        except Exception as e:
            self._append(f"[ERROR] {e}")
        finally:
            k32.CloseHandle(hProc)

        # Deduplicate is already enforced by 'seen'; just store & render (with current filter)
        self._all_strings = collected
        self._apply_filter()

        def _done():
            self._busy = False
            try:
                self._refresh_btn.configure(state="normal", text="Refresh")
            except Exception:
                pass
        self.after(0, _done)
            
class ProcessDetails(ctk.CTkToplevel):
    def __init__(self, master, dashboard: MalwareDashboard, pid: int):
        super().__init__(master)
        self.title(f"Process {pid} details")
        self.geometry("980x640")
        self.dashboard = dashboard
        self.pid = pid
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="#0E2536")
        top.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkLabel(top, text=f"PID {self.pid}", font=("Arial", 22, "bold"))
        header.pack(pady=(6, 4))

        # Info area
        self.info = ctk.CTkTextbox(top, height=300, wrap="word", font=("Consolas", 14), fg_color="#102A3C", text_color="white")
        self.info.pack(fill="both", expand=False, padx=6, pady=(6, 8))

        # Actions
        btns = ctk.CTkFrame(top, fg_color="transparent")
        btns.pack(fill="x", padx=6, pady=(4, 8))
        ctk.CTkButton(btns, text="Scan PID", command=self._scan_pid).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Strings", command=self._strings_pid).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="DNS/URLs", command=self._dns_pid_dialog).pack(side="left", padx=6)

        # Populate info safely
        self._fill_info_safe()

    def _fill_info_safe(self):
        try:
            p = psutil.Process(self.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
            self._set_info(f"Process unavailable: {e}\n(It may have exited or require elevation.)")
            return

        name = _safe_call(lambda: p.name())
        exe = _safe_call(lambda: p.exe())
        cmdline = _safe_call(lambda: " ".join(p.cmdline() or []))
        cwd = _safe_call(lambda: p.cwd())
        ppid = _safe_call(lambda: str(p.ppid()))
        user = _safe_call(lambda: p.username())
        started = _safe_call(lambda: _fmt_ts(p.create_time()))

        # connections (system-wide filter to avoid AccessDenied on per-proc)
        con_lines = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid == self.pid:
                    l = self._fmt_addr(c.laddr)
                    r = self._fmt_addr(c.raddr)
                    con_lines.append(f"{c.status:12} {l:23} -> {r:23}")
        except Exception:
            pass

        text = (
            f"Name: {name}\n"
            f"Exe: {exe}\n"
            f"Cmdline: {cmdline}\n"
            f"CWD: {cwd}\n"
            f"PPID: {ppid}\n"
            f"User: {user}\n"
            f"Started: {started}\n\n"
            "Active Connections:\n" + ("(none)\n" if not con_lines else "\n".join(con_lines[:300]))
        )
        self._set_info(text)

    def _fmt_addr(self, addr):
        if not addr:
            return ""
        try:
            if isinstance(addr, tuple):
                if len(addr) == 2:
                    return f"{addr[0]}:{addr[1]}"
                return ":".join(str(x) for x in addr)
            ip = getattr(addr, "ip", None)
            port = getattr(addr, "port", None)
            if ip is not None and port is not None:
                return f"{ip}:{port}"
            return str(addr)
        except Exception:
            return str(addr)

    def _set_info(self, text):
        self.info.configure(state="normal")
        self.info.delete("1.0", "end")
        self.info.insert("1.0", text)
        self.info.configure(state="disabled")

    # --- Actions ---
    def _scan_pid(self):
        def worker():
            try:
                extractor = self.dashboard.analysis_feature_extractor
                logger = self.dashboard.analysis_logger
                run_yara_pid(self.pid, self.dashboard, extractor, logger)
                messagebox.showinfo("Scan complete", f"PID {self.pid} scan finished. Check Analysis → Console.")
            except Exception as e:
                messagebox.showerror("Scan failed", str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _strings_pid(self):
        try:
            StringsViewer(self, self.pid)
        except Exception as e:
            messagebox.showerror("Strings error", str(e))

    def _dns_pid_dialog(self):
        def worker():
            try:
                extractor = DNSExtractor()
                try:
                    domains, removed, proc_info = extractor.extract_from_process(self.pid)
                except TypeError:
                    domains = extractor.extract_from_process(self.pid, include_children=False)
                    removed, proc_info = [], {}

                unique = sorted(set(domains or []))
                self.after(0, lambda: self._show_dns_dialog(unique))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("DNS/URL Extract failed", str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def _show_dns_dialog(self, items):
        dlg = ctk.CTkToplevel(self)
        dlg.title(f"DNS/URLs — PID {self.pid}")
        dlg.geometry("700x500")

        top = ctk.CTkFrame(dlg, fg_color="#0E2536")
        top.pack(fill="both", expand=True, padx=8, pady=8)

        btns = ctk.CTkFrame(top, fg_color="transparent")
        btns.pack(fill="x")
        ctk.CTkButton(btns, text="Copy All", command=lambda: self._copy_to_clipboard("\n".join(items))).pack(side="right")

        listbox = ctk.CTkTextbox(top, wrap="none", font=("Consolas", 12), fg_color="#102A3C", text_color="white")
        listbox.pack(fill="both", expand=True, pady=(6,0))
        if items:
            listbox.insert("1.0", "\n".join(items))
        else:
            listbox.insert("1.0", "(none)")
        listbox.configure(state="disabled")

        # per-item copy footer (simple field + button)
        foot = ctk.CTkFrame(top, fg_color="transparent")
        foot.pack(fill="x", pady=(6,0))
        sel = tk.StringVar(value="")
        ent = ctk.CTkEntry(foot, textvariable=sel, width=520, placeholder_text="Paste an item here to copy")
        ent.pack(side="left", padx=(0,6))
        ctk.CTkButton(foot, text="Copy", command=lambda: self._copy_to_clipboard(sel.get())).pack(side="left")

    def _copy_to_clipboard(self, text):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
        except Exception:
            pass



# ========== Combined Analysis Panel (optional/legacy) ==========
class CombinedAnalysisPanel(ctk.CTkFrame):
    def __init__(self, master, dashboard, **kwargs):
        super().__init__(master, fg_color="#0E2536", **kwargs)
        self.dashboard = dashboard
        self._build()

    def _build(self):
        # Processes section (live)
        proc_panel = ProcessPanel(self, dashboard=self.dashboard)
        proc_panel.pack(fill="both", expand=True, padx=8, pady=8)

        # Recent log tail (simple addition under the process panel)
        logs = ctk.CTkTextbox(self, height=120, wrap="none", font=("Consolas", 12), fg_color="#102A3C", text_color="white")
        logs.pack(fill="x", padx=8, pady=(0,8))
        logs.insert("1.0", "\n".join(self._read_last_log_lines()))
        logs.configure(state="disabled")

    def _read_last_log_lines(self):
        path = "C:\\Users\\REM\\Desktop\\YarWatch_Data.txt"
        lines = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-50:]
        except Exception:
            lines = ["No log found yet."]
        return [l.rstrip("\n") for l in lines]


# ========== Entry Point ======
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = MalwareDashboard()
    app.mainloop()
