# core/traffic.py
from __future__ import annotations
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import threading
import time
import socket
import subprocess
import os
import json
from collections import defaultdict
from datetime import datetime

# ========= common config =========
EXCLUDED_REMOTE = os.environ.get("MAD_EXCLUDED_REMOTE", "10.1.64.2:445")
REFRESH_SECS = float(os.environ.get("MAD_TRAFFIC_INTERVAL", "2.0"))

try:
    from core import config  # optional shared constants
    DEFAULT_THQ_IP = os.path.join(getattr(config, "SCRIPTS_DIR", ""), "thqIP.py")
except Exception:
    DEFAULT_THQ_IP = r"\\10.1.64.2\pdc\!Persistent_Folder\1YarWatch1\YarWatch_Scripts\thqIP.py"

THQ_IP_SCRIPT = os.environ.get("MAD_THQ_IP_SCRIPT", DEFAULT_THQ_IP)


# ========= LEFT: Simplified live connections (PID | Process | Remote | Host | THQ) =========
class TrafficPanel(ctk.CTkFrame):
    def __init__(self, master, on_scan_pid=None, on_view_dns=None, **kwargs):
        super().__init__(master, fg_color="#0E2536", **kwargs)
        self.on_scan_pid = on_scan_pid
        self.on_view_dns = on_view_dns

        self._watch = tk.BooleanVar(value=True)
        self._building = False
        self._rows_by_key: dict[tuple[int, str], str] = {}  # (pid, remote)->iid
        self._host_cache: dict[str, str] = {}
        self._thq_cache: dict[str, str] = {}
        self._resolver_pool = threading.Semaphore(8)
        self._thq_pool = threading.Semaphore(4)

        self._build_ui()
        self._tick()

    def _build_ui(self):
        tb = ctk.CTkFrame(self, fg_color="#0B1F2C")
        tb.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(tb, text="Network ", font=("Arial", 18, "bold")).pack(side="left", padx=(8, 6))
        self.pause_switch = ctk.CTkSwitch(tb, text="Live", variable=self._watch, command=self._on_watch_toggled)
        self.pause_switch.pack(side="right", padx=(6, 10))

        wrap = ctk.CTkFrame(self, fg_color="#0E2536")
        wrap.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        cols = ("PID", "Process", "Remote", "Host", "THQ")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("PID", width=70, anchor="e")
        self.tree.column("Process", width=220, anchor="w")
        self.tree.column("Remote", width=220, anchor="w")
        self.tree.column("Host", width=260, anchor="w")
        self.tree.column("THQ", width=160, anchor="w")
        self.tree.pack(fill="both", expand=True)

        style = ttk.Style(self.tree)
        style.configure("Treeview", background="#0E2536", fieldbackground="#0E2536", foreground="white", rowheight=24)
        style.map("Treeview", background=[("selected", "#1d4ed8")])

        self.tree.bind("<Double-1>", self._on_double_click_row)
        self.tree.bind("<Button-1>", self._on_left_click)
        self.tree.bind("<Button-3>", self._open_context_menu)

    def _on_watch_toggled(self):
        if self._watch.get():
            self._tick()

    def _tick(self):
        if not self._watch.get():
            return
        self.refresh_async()
        self.after(int(REFRESH_SECS * 1000), self._tick)

    def refresh_async(self):
        if self._building:
            return
        self._building = True
        threading.Thread(target=self._rebuild_model, daemon=True).start()

    def _rebuild_model(self):
        rows = {}
        procnames = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status != psutil.CONN_ESTABLISHED:
                    continue
                if not c.raddr:
                    continue
                pid = c.pid or 0
                remote = f"{c.raddr.ip}:{c.raddr.port}"
                if remote == EXCLUDED_REMOTE:
                    continue
                name = procnames.get(pid)
                if name is None:
                    try:
                        name = psutil.Process(pid).name() if pid else "System"
                    except Exception:
                        name = "N/A"
                    procnames[pid] = name

                key = (pid, remote)
                rows[key] = {
                    "PID": str(pid),
                    "Process": name,
                    "Remote": remote,
                    "Host": self._host_cache.get(c.raddr.ip, "…"),
                    "THQ": self._thq_cache.get(c.raddr.ip, "…"),
                    "ip": c.raddr.ip
                }

                if rows[key]["Host"] == "…":
                    threading.Thread(target=self._resolve_host_bg, args=(c.raddr.ip,), daemon=True).start()
                if rows[key]["THQ"] == "…":
                    threading.Thread(target=self._resolve_thq_bg, args=(c.raddr.ip,), daemon=True).start()
        except Exception:
            pass
        self.after(0, lambda: self._render(rows))

    def _resolve_host_bg(self, ip: str):
        if ip in self._host_cache:
            return
        with self._resolver_pool:
            try:
                host = "" if ip in ("127.0.0.1", "0.0.0.0", "*") else socket.gethostbyaddr(ip)[0]
            except Exception:
                host = ""
            self._host_cache[ip] = host
        self.after(0, self._refresh_hosts)

    def _resolve_thq_bg(self, ip: str):
        if ip in self._thq_cache:
            return
        family = "Unknown"
        if os.path.exists(THQ_IP_SCRIPT):
            with self._thq_pool:
                try:
                    out = subprocess.run(["python", THQ_IP_SCRIPT, ip], capture_output=True, text=True, timeout=10).stdout
                    for line in out.splitlines():
                        if "Family Name:" in line:
                            family = line.split(":", 1)[1].strip() or "Unknown"
                            break
                except Exception:
                    family = "Unknown"
        self._thq_cache[ip] = family
        self.after(0, self._refresh_thq)

    def _render(self, rows: dict):
        existing_keys = set(self._rows_by_key.keys())
        new_keys = set(rows.keys())
        for key in sorted(new_keys):
            v = rows[key]
            iid = self._rows_by_key.get(key)
            tup = (v["PID"], v["Process"], v["Remote"], v["Host"], v["THQ"])
            if iid:
                self.tree.item(iid, values=tup)
            else:
                iid = self.tree.insert("", "end", values=tup)
                self._rows_by_key[key] = iid
        for key in (existing_keys - new_keys):
            iid = self._rows_by_key.pop(key, None)
            if iid:
                try:
                    self.tree.delete(iid)
                except Exception:
                    pass
        self._building = False

    def _refresh_hosts(self):
        for key, iid in list(self._rows_by_key.items()):
            ip = key[1].split(":")[0]
            host = self._host_cache.get(ip)
            if host is not None:
                vals = list(self.tree.item(iid, "values"))
                if vals and vals[3] != host:
                    vals[3] = host
                    self.tree.item(iid, values=tuple(vals))

    def _refresh_thq(self):
        for key, iid in list(self._rows_by_key.items()):
            ip = key[1].split(":")[0]
            fam = self._thq_cache.get(ip)
            if fam is not None:
                vals = list(self.tree.item(iid, "values"))
                if vals and vals[4] != fam:
                    vals[4] = fam
                    self.tree.item(iid, values=tuple(vals))

    # interactions
    def _row_info_under_mouse(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return None
        vals = self.tree.item(iid, "values")
        if not vals or len(vals) < 5:
            return None
        try:
            return {
                "pid": int(vals[0]),
                "proc": vals[1],
                "remote": vals[2],
                "host": vals[3],
                "thq": vals[4],
                "iid": iid,
            }
        except Exception:
            return None

    def _on_left_click(self, event):
        col = self.tree.identify_column(event.x)  # '#3' => 3rd column
        if col != "#3":
            return
        info = self._row_info_under_mouse(event)
        if not info:
            return
        ip = info["remote"].split(":", 1)[0]
        self._show_connections_for_remote(ip)

    def _on_double_click_row(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        pid = int(vals[0])
        self._show_connections_for_pid(pid)

    def _open_context_menu(self, event):
        info = self._row_info_under_mouse(event)
        if not info:
            return
        self.tree.selection_set(info["iid"])
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Show connections for PID", command=lambda: self._show_connections_for_pid(info["pid"]))
        m.add_command(label="Show all for this Remote", command=lambda: self._show_connections_for_remote(info["remote"].split(":")[0]))
        if self.on_scan_pid:
            m.add_separator()
            m.add_command(label="Scan PID with YARA", command=lambda: self.on_scan_pid(info["pid"]))
        if self.on_view_dns:
            m.add_command(label="Extract DNS / URLs", command=lambda: self.on_view_dns(info["pid"]))
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def _collect_connections(self, where):
        out = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status != psutil.CONN_ESTABLISHED:
                    continue
                if not c.raddr:
                    continue
                if not where(c):
                    continue
                pid = c.pid or 0
                try:
                    name = psutil.Process(pid).name() if pid else "System"
                except Exception:
                    name = "N/A"
                local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                remote = f"{c.raddr.ip}:{c.raddr.port}"
                out.append({
                    "pid": pid, "proc": name,
                    "proto": "TCP" if c.type == psutil.SOCK_STREAM else "UDP",
                    "local": local, "remote": remote, "state": c.status
                })
        except Exception:
            pass
        return out

    def _open_connections_window(self, title: str, rows: list[dict], group_by_pid: bool = False):
        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("820x500")
        win.focus()

        tb = ctk.CTkFrame(win, fg_color="#0B1F2C")
        tb.pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkLabel(tb, text=title, font=("Arial", 18, "bold")).pack(side="left", padx=8)
        ctk.CTkButton(tb, text="Refresh", width=80, command=lambda: self._refresh_connections_window(win, group_by_pid)).pack(side="right", padx=8)

        cols = ("PID", "Process", "Proto", "Local", "Remote", "State")
        tv = ttk.Treeview(win, columns=cols, show="headings", height=18)
        for c in cols:
            tv.heading(c, text=c)
        tv.column("PID", width=70, anchor="e")
        tv.column("Process", width=220, anchor="w")
        tv.column("Proto", width=70, anchor="w")
        tv.column("Local", width=200, anchor="w")
        tv.column("Remote", width=200, anchor="w")
        tv.column("State", width=100, anchor="w")
        tv.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        win._traffic_tv = tv

        self._populate_connections_tree(tv, rows, group_by_pid)

    def _refresh_connections_window(self, win: ctk.CTkToplevel, group_by_pid: bool):
        title = win.title()
        if title.startswith("Active connections for PID"):
            pid = int(title.split()[-1])
            rows = self._collect_connections(lambda c: c.pid == pid)
        elif title.startswith("Active connections to "):
            ip = title.split()[-1]
            rows = self._collect_connections(lambda c: c.raddr and c.raddr.ip == ip)
        else:
            rows = []
        self._populate_connections_tree(win._traffic_tv, rows, group_by_pid)

    def _populate_connections_tree(self, tv: ttk.Treeview, rows: list[dict], group_by_pid: bool):
        tv.delete(*tv.get_children())
        if not group_by_pid:
            for r in rows:
                tv.insert("", "end", values=(r["pid"], r["proc"], r["proto"], r["local"], r["remote"], r["state"]))
            return
        groups = defaultdict(list)
        for r in rows:
            groups[(r["pid"], r["proc"])].append(r)
        for (pid, name) in sorted(groups.keys(), key=lambda k: (k[1].lower(), k[0])):
            parent = tv.insert("", "end", values=(pid, name, "", "", "", ""))
            for r in groups[(pid, name)]:
                tv.insert(parent, "end", values=(r["pid"], r["proc"], r["proto"], r["local"], r["remote"], r["state"]))

    def _show_connections_for_pid(self, pid: int):
        rows = self._collect_connections(lambda c: c.pid == pid)
        self._open_connections_window(f"Active connections for PID {pid}", rows)

    def _show_connections_for_remote(self, ip: str):
        rows = self._collect_connections(lambda c: c.raddr and c.raddr.ip == ip)
        self._open_connections_window(f"Active connections to {ip}", rows, group_by_pid=True)


# ========= RIGHT: HTTP panel (Live 80/443 sockets OR HAR import) =========
class HttpTrafficPanel(ctk.CTkFrame):
    """
    Two modes:
      1) Live sockets (port 80/443): displays proto/host/url* placeholders (HTTPS won't reveal URL).
      2) HAR file: load a HAR (from Fiddler/mitmproxy/Chrome) and display Method, Host, URL, Status, Size, Time.

    Click a row -> opens details popup (headers if HAR; basics if live).
    """
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="#0E2536", **kwargs)
        self._watch = tk.BooleanVar(value=True)
        self._mode = tk.StringVar(value="Live")  # Live | HAR
        self._building = False
        self._rows = []
        self._host_cache = {}
        self._har_path = tk.StringVar(value="")

        self._build_ui()
        self._tick()

    def _build_ui(self):
        tb = ctk.CTkFrame(self, fg_color="#0B1F2C")
        tb.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(tb, text="HTTP", font=("Arial", 18, "bold")).pack(side="left", padx=(8, 6))

        opt = ctk.CTkOptionMenu(tb, values=["Live", "HAR"], variable=self._mode, command=lambda _v: self._mode_changed())
        opt.pack(side="right", padx=6)

        self.watch = ctk.CTkSwitch(tb, text="Live", variable=self._watch, command=self._on_watch_toggled)
        self.watch.pack(side="right", padx=(6, 10))

        # HAR controls (hidden unless HAR mode)
        self.har_entry = ctk.CTkEntry(tb, textvariable=self._har_path, placeholder_text="Select a HAR file", width=320)
        self.har_btn = ctk.CTkButton(tb, text="Open HAR", width=90, command=self._choose_har)

        wrap = ctk.CTkFrame(self, fg_color="#0E2536")
        wrap.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        cols = ("Time", "Method", "Host", "URL", "Status", "Size (KB)", "PID", "Process")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("Time", width=130, anchor="w")
        self.tree.column("Method", width=70, anchor="w")
        self.tree.column("Host", width=210, anchor="w")
        self.tree.column("URL", width=320, anchor="w")
        self.tree.column("Status", width=70, anchor="e")
        self.tree.column("Size (KB)", width=90, anchor="e")
        self.tree.column("PID", width=70, anchor="e")
        self.tree.column("Process", width=160, anchor="w")
        self.tree.pack(fill="both", expand=True)

        style = ttk.Style(self.tree)
        style.configure("Treeview", background="#0E2536", fieldbackground="#0E2536", foreground="white", rowheight=24)
        style.map("Treeview", background=[("selected", "#1d4ed8")])

        self.tree.bind("<Double-1>", self._on_open_details)
        self._layout_har_controls()

    def _layout_har_controls(self):
        # show/hide HAR controls based on mode
        parent = self.har_entry.master
        if self._mode.get() == "HAR":
            self.har_entry.pack_forget(); self.har_btn.pack_forget()
            self.har_entry.pack(side="left", padx=(10, 6))
            self.har_btn.pack(side="left", padx=(0, 8))
        else:
            self.har_entry.pack_forget(); self.har_btn.pack_forget()

    def _on_watch_toggled(self):
        if self._watch.get():
            self._tick()

    def _mode_changed(self):
        self._layout_har_controls()
        if self._mode.get() == "HAR":
            self._watch.set(False)  # HAR isn't "live"; manual load
        else:
            self._watch.set(True)
            self._tick()

    def _choose_har(self):
        path = filedialog.askopenfilename(title="Select HAR file", filetypes=[("HAR files", "*.har"), ("JSON", "*.json"), ("All files", "*.*")])
        if path:
            self._har_path.set(path)
            self._load_har(path)

    def _tick(self):
        if self._mode.get() != "Live" or not self._watch.get():
            return
        self.refresh_async()
        self.after(1200, self._tick)

    def refresh_async(self):
        if self._building:
            return
        self._building = True
        threading.Thread(target=self._build_live_rows, daemon=True).start()

    # ---- Live sockets (approx HTTP view) ----
    def _build_live_rows(self):
        rows = []
        try:
            now = datetime.now().strftime("%H:%M:%S")
            procnames = {}
            for c in psutil.net_connections(kind="inet"):
                if c.status != psutil.CONN_ESTABLISHED:
                    continue
                if not c.raddr:
                    continue
                # Only 80/443 to approximate HTTP/TLS
                rport = int(getattr(c.raddr, "port", 0) or 0)
                if rport not in (80, 443):
                    continue
                pid = c.pid or 0
                try:
                    name = procnames.get(pid) or (psutil.Process(pid).name() if pid else "System")
                    procnames[pid] = name
                except Exception:
                    name = "N/A"
                host = self._host_cache.get(c.raddr.ip)
                if host is None:
                    host = ""
                    threading.Thread(target=self._resolve_host_bg, args=(c.raddr.ip,), daemon=True).start()
                proto = "HTTP" if rport == 80 else "TLS"
                rows.append({
                    "Time": now,
                    "Method": proto,                 # placeholder (no DPI)
                    "Host": host or c.raddr.ip,
                    "URL": "(session)",              # we can't see path without a proxy
                    "Status": "",
                    "SizeKB": "",
                    "PID": pid,
                    "Process": name,
                    "_kind": "live",
                    "_tuple": (c.laddr.ip if c.laddr else "", getattr(c.laddr, "port", 0), c.raddr.ip, rport)
                })
        except Exception:
            pass
        self.after(0, lambda: self._render_rows(rows))

    def _resolve_host_bg(self, ip: str):
        try:
            host = "" if ip in ("127.0.0.1", "0.0.0.0", "*") else socket.gethostbyaddr(ip)[0]
        except Exception:
            host = ""
        self._host_cache[ip] = host
        self.after(0, lambda: self._repaint_hosts(ip))

    def _repaint_hosts(self, ip: str):
        for iid in self.tree.get_children(""):
            vals = list(self.tree.item(iid, "values"))
            if not vals:
                continue
            # if URL col is "(session)" this was a live row; compare host ip
            if vals[3] == "(session)":
                continue
            # vals: Time, Method, Host, URL, Status, SizeKB, PID, Process
        # (No-op: hosts refresh on next tick)

    # ---- HAR mode ----
    def _load_har(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("HAR load failed", str(e))
            return

        entries = data.get("log", {}).get("entries", [])
        rows = []
        for e in entries:
            started = e.get("startedDateTime", "")
            try:
                ts = datetime.fromisoformat(started.replace("Z","+00:00")).strftime("%H:%M:%S")
            except Exception:
                ts = started or ""
            req = e.get("request", {})
            res = e.get("response", {})
            method = req.get("method", "")
            url = req.get("url", "")
            host = ""
            # try to pull Host header if present
            for h in req.get("headers", []):
                if h.get("name", "").lower() == "host":
                    host = h.get("value", "")
                    break
            if not host:
                try:
                    host = url.split("/")[2]
                except Exception:
                    host = ""
            status = res.get("status", "")
            size = res.get("bodySize", 0)
            size_kb = round((size or 0) / 1024.0, 1)

            rows.append({
                "Time": ts,
                "Method": method,
                "Host": host,
                "URL": url,
                "Status": status,
                "SizeKB": size_kb,
                "PID": "",         # HAR doesn't include PID
                "Process": "",
                "_kind": "har",
                "_raw": e
            })
        self._rows = rows
        self._render_rows(rows)

    def _render_rows(self, rows):
        self.tree.delete(*self.tree.get_children(""))
        for r in rows:
            self.tree.insert("", "end", values=(
                r.get("Time",""), r.get("Method",""), r.get("Host",""),
                r.get("URL",""), r.get("Status",""), r.get("SizeKB",""),
                r.get("PID",""), r.get("Process","")
            ))
        self._building = False

    def _on_open_details(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        time_s, method, host, url, status, sizekb, pid, proc = vals
        top = ctk.CTkToplevel(self)
        top.title(f"{method} {host}")
        top.geometry("780x520")

        tb = ctk.CTkFrame(top, fg_color="#0B1F2C")
        tb.pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkLabel(tb, text=f"{method} {url or host}", font=("Arial", 16, "bold")).pack(side="left", padx=8)

        box = ctk.CTkTextbox(top, wrap="word", font=("Consolas", 12), fg_color="#102A3C", text_color="white")
        box.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # If HAR we try to show request/response headers
        if self._mode.get() == "HAR":
            # find the raw entry by URL+method+time (best-effort)
            entry = None
            for r in self._rows:
                if r["_kind"] == "har" and r["URL"] == url and r["Method"] == method and r["Time"] == time_s:
                    entry = r.get("_raw")
                    break
            if entry:
                req = entry.get("request", {})
                res = entry.get("response", {})
                req_h = "\n".join(f"{h.get('name')}: {h.get('value')}" for h in req.get("headers", []))
                res_h = "\n".join(f"{h.get('name')}: {h.get('value')}" for h in res.get("headers", []))
                text = []
                text.append("[Request]")
                text.append(f"{req.get('method','')} {req.get('url','')}")
                text.append(req_h or "(no headers)")
                text.append("")
                text.append("[Response]")
                text.append(f"Status: {res.get('status','')} {res.get('statusText','')}")
                text.append(res_h or "(no headers)")
                box.insert("1.0", "\n".join(text))
                box.configure(state="disabled")
                return

        # Live mode: show what we know
        text = []
        text.append(f"Time: {time_s}")
        text.append(f"Proto/Method: {method}")
        text.append(f"Host: {host}")
        if url:
            text.append(f"URL: {url}")
        if status:
            text.append(f"Status: {status}")
        if sizekb:
            text.append(f"Size: {sizekb} KB")
        if pid:
            text.append(f"PID: {pid}")
            text.append(f"Process: {proc}")
        else:
            text.append("(No headers available in live mode. Use a proxy/HAR for full details.)")
        box.insert("1.0", "\n".join(text))
        box.configure(state="disabled")


# ========= COMPOSITE: Two side-by-side panels =========
class TrafficTwoPane(ctk.CTkFrame):
    """
    Left: TrafficPanel (sockets)
    Right: HttpTrafficPanel (HTTP/TLS live or HAR)
    """
    def __init__(self, master, on_scan_pid=None, on_view_dns=None, **kwargs):
        super().__init__(master, fg_color="#0E2536", **kwargs)
        self.grid_columnconfigure(0, weight=1, uniform="cols")
        self.grid_columnconfigure(1, weight=1, uniform="cols")
        self.grid_rowconfigure(0, weight=1)

        left = TrafficPanel(self, on_scan_pid=on_scan_pid, on_view_dns=on_view_dns)
        right = HttpTrafficPanel(self)

        left.grid(row=0, column=0, sticky="nsew", padx=(8,4), pady=8)
        right.grid(row=0, column=1, sticky="nsew", padx=(4,8), pady=8)
