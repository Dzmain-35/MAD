# yarwatch/gui.py

import os
import tkinter as tk
import queue
import customtkinter
import threading
import subprocess
import webbrowser
import psutil
import datetime
from tkinter import ttk
import time
from tkinter import filedialog, simpledialog
from PIL import Image
from yarwatch.config import icon_path, logo_path, yar_report_script, daily_mal_script, ioc_search_script, scan_gui_script
from yarwatch.scanner import run_yara_file, run_yara_pid
from yarwatch.collapsible_frame import CollapsibleScanFrame
from yarwatch.config import disallowed_processes 


def get_score_color(level):
    return {
        "Critical": "#cc0000",
        "High": "#ff6600",
        "Medium": "#ffcc00",
        "Low": "#00cc66"
    }.get(level, "white")

def get_threat_color(level):
    return {
        "Critical": "#990000",
        "High": "#cc5200",
        "Medium": "#e6b800",
        "Low": "#006633"
    }.get(level, "#333333")

class YarWatchGUI:
    def __init__(self, root, feature_extractor, logger, output_queue, monitor=None):
        self.root = root
        self.feature_extractor = feature_extractor
        self.output_queue = output_queue
        self.logger = logger
        self.monitor = monitor
        self.logger.set_gui_queue(self.output_queue)
        self.stop_process_thread = False
        self.pid_node_map = {}
        self.root.title("YarWatch")
        self.root.geometry("900x500")
        self.default_height = 500
        self.expanded_height = 700  # or whatever looks best

        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_rowconfigure(5, weight=1)  # Ensure process panel grows
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(2, weight=1)
        self.root.configure(fg_color="#0E2536")
        self.root.iconbitmap(icon_path)

        self.root.after(100, self.process_output_queue)

        self.process_panel_visible = False

        self.build_menu()
        self.build_layout()

    def build_menu(self):
        self.menu_bar = tk.Menu(self.root)
        file_menu = tk.Menu(self.menu_bar, tearoff=0, bg="#0E2536", fg="white", activebackground="#cc0000", activeforeground="black")
        file_menu.add_command(label="Create Report", command=self.create_report)
        file_menu.add_command(label="Daily Malware", command=self.run_daily)
        file_menu.add_command(label="IOC Search", command=self.search)
        file_menu.add_command(label="CyberChef", command=self.cyberchef)
        file_menu.add_command(label="Threat HQ", command=self.thq)
        file_menu.add_command(label="DNS Extractor", command=self.dns_extractor)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=self.menu_bar)

    def build_layout(self):
        '''img = customtkinter.CTkImage(light_image=Image.open(logo_path), size=(150, 150))
        self.image_label = customtkinter.CTkLabel(self.root, image=img, text="")
        self.image_label.grid(row=0, column=0, columnspan=3, pady=20, sticky="nsew")
        self.root.grid_rowconfigure(2, weight=0)'''
        btn_color = "#cc0000"
        hover_color = "#800000"
        font = ("Roboto", 30)

        self.title_button = customtkinter.CTkButton(self.root, text="YarWatch", font=("Roboto", 40), fg_color=btn_color, hover_color=hover_color, height=65, command=self.toggle_watch)
        self.title_button.grid(row=1, column=1, padx=20, pady=(20, 15), sticky="nsew")

        self.scan_file_button = customtkinter.CTkButton(self.root, text="Scan File", font=font, fg_color=btn_color, hover_color=hover_color, height=65, command=self.scan_file)
        self.scan_file_button.grid(row=1, column=0, padx=20, pady=(20, 15), sticky="nsew")

        self.scan_pid_button = customtkinter.CTkButton(self.root, text="Scan PID", font=font, fg_color=btn_color, hover_color=hover_color, height=65, command=self.scan_pid)
        self.scan_pid_button.grid(row=1, column=2, padx=20, pady=(20, 15), sticky="nsew")

        self.running_processes_button = customtkinter.CTkButton(self.root, text="▶ Running Processes", font=font, fg_color=btn_color, hover_color=hover_color, height=45, command=self.open_processs_button)
        self.running_processes_button.grid(row=4, column=1, padx=10, pady=10, sticky="nsew")

        self.process_panel = customtkinter.CTkFrame(self.root, fg_color="#0E2536")
        self.process_tree = ttk.Treeview(self.process_panel, columns=("pid", "user"), show="tree headings")
        self.process_tree.heading("#0", text="Process Name", anchor="w")
        self.process_tree.heading("pid", text="PID", anchor="w")
        self.process_tree.heading("user", text="User", anchor="w")

        self.process_tree.column("#0", width=300, stretch=True)
        self.process_tree.column("pid", width=80, stretch=False)
        self.process_tree.column("user", width=150, stretch=False)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#0E2536", foreground="white", fieldbackground="#0E2536", rowheight=28, font=("Consolas", 13))
        style.map("Treeview", background=[("selected", "#cc0000")], foreground=[("selected", "white")])

        self.process_tree.pack(fill="both", expand=True, padx=10, pady=5)

        self.process_tree.bind("<<TreeviewSelect>>", self.on_process_tree_click)


        self.scroll_border_frame = customtkinter.CTkFrame(self.root, border_width=10, border_color="white", corner_radius=10, fg_color="transparent")
        self.scroll_border_frame.grid(row=3, column=0, columnspan=3, padx=20, pady=5, sticky="nsew")

        self.scroll_frame = customtkinter.CTkFrame(self.scroll_border_frame)
        self.scroll_frame.pack(fill="both", expand=True, padx=1.5, pady=1.5)

        self.canvas = tk.Canvas(self.scroll_frame, bg="#0E2536", highlightthickness=1)
        self.canvas.pack(side="left", fill="both", expand=True)
        
        self.scrollbar = tk.Scrollbar(self.scroll_frame, orient="vertical", command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        self.canvas.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", _on_mousewheel))
        self.canvas.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))

        self.scrollable_inner = customtkinter.CTkFrame(self.canvas, fg_color="#0E2536")
        self.scrollable_inner_id = self.canvas.create_window((0, 0), window=self.scrollable_inner, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.scrollable_inner_id, width=e.width))

    def open_processs_button(self):
        if self.process_panel_visible:
            self.process_panel.grid_forget()
            self.running_processes_button.configure(text="▶ Running Processes")
            self.root.geometry(f"922x{self.default_height}")
            self.process_panel_visible = False
            self.stop_process_thread = True
        else:
            self.process_panel.grid(row=5, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="nsew")
            self.running_processes_button.configure(text="▼ Running Processes")
            self.root.geometry(f"922x{self.expanded_height}")
            self.process_panel_visible = True
            self.stop_process_thread = False
            self.seen_pids = set()
            threading.Thread(target=self.gui_monitor_loop, daemon=True).start()


 
    def gui_monitor_loop(self):

        existing_pids = {p.pid for p in psutil.process_iter()}
        while not self.stop_process_thread:
            time.sleep(1)
            current_pids = {p.pid for p in psutil.process_iter()}
            new_pids = current_pids - existing_pids

            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    if name.lower() in (p.lower() for p in disallowed_processes):
                        continue  # Skip blacklisted
                    self.root.after(0, self._add_embedded_process, name, pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            existing_pids = current_pids


    def _add_embedded_process(self, name, pid):
        try:
            proc = psutil.Process(pid)
            user = proc.username()
            parent_pid = proc.ppid()
        except Exception:
            user = "N/A"
            parent_pid = None

        parent_id = self.pid_node_map.get(parent_pid, "")
        node_id = self.process_tree.insert(parent_id, "end", text=name, values=(pid, user))
        self.pid_node_map[pid] = node_id
    def show_process_popup(self, name, pid):
        info = self.get_process_info(pid)

        popup = tk.Toplevel(self.root)
        popup.title(f"Process Info: {name} (PID {pid})")
        popup.geometry("520x420")
        popup.configure(bg="#0E2536")

        info_box = tk.Text(popup, wrap="word", bg="#0E2536", fg="white", font=("Roboto", 10), relief="flat", borderwidth=10)
        info_box.pack(fill="both", expand=True)

        for key, value in info.items():
            line = f"{key}: {value}\n"
            info_box.insert("end", line)

        info_box.configure(state="disabled")

        scan_button = tk.Button(popup, text="Scan This PID", bg="#cc0000", fg="white", command=lambda: self.scan_pid_direct(pid))
        scan_button.pack(pady=8)

    def on_process_tree_click(self, event):
        selected = self.process_tree.selection()
        if not selected:
            return

        item_id = selected[0]
        pid = self.process_tree.item(item_id, "values")[0]

        try:
            pid = int(pid)
            name = self.process_tree.item(item_id, "text")
            self.show_process_popup(name, pid)
        except Exception as e:
            print(f"[Error] Could not parse PID: {e}")

    def get_process_info(self, pid):
        try:
            proc = psutil.Process(pid)
            info = {
                "Name": proc.name(),
                "PID": pid,
                "Parent PID": proc.ppid(),
                "Executable": proc.exe(),
                "Cmdline": " ".join(proc.cmdline()),
                "CWD": proc.cwd(),
                "User": proc.username(),
                "Status": proc.status(),
                "Start Time": datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                "Memory": f"{proc.memory_info().rss // (1024 * 1024)} MB",
                "CPU": f"{proc.cpu_percent(interval=0.1)}%",
            }

            open_files = proc.open_files()
            info["Open Files"] = ", ".join(f.path for f in open_files) if open_files else "None"

            conns = proc.connections()
            info["Connections"] = ", ".join(f"{c.laddr}->{c.raddr}" for c in conns if c.raddr) or "None"

            return info
        except Exception as e:
            return {"Error": str(e)}

    def scan_pid_direct(self, pid):
        threading.Thread(target=run_yara_pid, args=(pid, self, self.feature_extractor, self.logger), daemon=True).start()

    def update_output(self, message):
        print("[DEBUG] update_output received:", message)
        self.output_queue.put(message)
        if "[Monitor] New process:" in message and self.process_panel_visible:
            try:
                process_info = message.split("New process: ")[1].strip()
                self.root.after(0, self._add_process_to_listbox, process_info)
            except Exception:
                pass

    def _add_process_to_listbox(self, text):
        self.process_listbox.insert("end", text)
        self.process_listbox.yview_moveto(1.0)

    def update_collapsible_output(self, result_dict):
        rule = result_dict.get("rule", "")
        score = result_dict.get("threat_score", "--")
        level = result_dict.get("risk_level", "--")
        target = result_dict.get("target", "unknown")
        thq = result_dict.get("thq_family")
        target_type = result_dict.get("target_type")

        if target_type == "file":
            name = os.path.basename(target)
        elif target_type == "pid":
            name = result_dict.get("process_name") or f"PID {target}"
        else:
            name = str(target)

        if rule:
            header = f"  {name} | Rule: {rule} | Score: {score} ({level})"
        elif thq:
            header = f"  {name} | THQ Match: {thq} | Score: {score} ({level})"
        else:
            header = f"  {name} | No Match: | Score: {score} ({level})"

        lines = []
        lines.append(f"Matched Rule: {rule}")
        lines.append("==================================================================")
        if result_dict.get("strings"):
            lines.append("YARA String Matches:")
            lines.extend(f"  - {s}" for s in result_dict["strings"][:10])

        if result_dict.get("target_type") == "file":
            lines.append("==================================================================")
            lines.append("File Details:")
            lines.append("==================================================================")
            lines.append(f"File Name: {os.path.basename(result_dict.get('target', ''))}")
            lines.append(f"MD5: {result_dict.get('md5', 'N/A')}")
            lines.append(f"SHA256: {result_dict.get('sha256', 'N/A')}")
            lines.append(f"File Size: {result_dict.get('size', 'N/A')} bytes")
            lines.append("==================================================================")
            lines.append(f"IMPHASH: {result_dict.get('imphash', 'N/A')}")
            lines.append("==================================================================")

        if result_dict.get("thq_family"):
            lines.append(f"THQ Family: {result_dict['thq_family']}")
        else:
            lines.append("\nTHQ Family: None")
            lines.append("==================================================================")

        vt_hits = result_dict.get("vt_hits", "N/A")
        lines.append(f"VirusTotal Hits: {vt_hits}")
        lines.append("==================================================================")

        if result_dict.get("network_output"):
            lines.append("Active Connections:")
            lines.extend(f"  {line}" for line in result_dict["network_output"].splitlines())
            lines.append("==================================================================")

        domains = result_dict.get("dns_domains", [])
        if domains:
            lines.append("Suspicious Domains:")
            lines.extend(f"  - {d}" for d in domains[:10])
        else:
            lines.append("\nSuspicious Domains: None")

        color = get_threat_color(level)
        self.scroll_border_frame.configure(border_color=color)

        panel = CollapsibleScanFrame(
            self.scrollable_inner,
            header,
            lines,
            color=color,
            result_dict=result_dict,
            gui=self)
        panel.pack(fill="x", expand=True, padx=20, pady=5)

    def process_output_queue(self):
        while not self.output_queue.empty():
            msg = self.output_queue.get()
            print(msg)
        self.root.after(100, self.process_output_queue)

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            threading.Thread(target=run_yara_file, args=(file_path, self, self.feature_extractor, self.logger)).start()

    def scan_pid(self):
        pid = simpledialog.askinteger("Input", "Enter PID:")
        if pid:
            threading.Thread(target=run_yara_pid, args=(pid, self, self.feature_extractor, self.logger), daemon=True).start()

    def toggle_watch(self):
        if not self.monitor:
            self.logger.log("[Monitor] Monitor not available.")
            return

        if self.monitor.running:
            self.monitor.stop()
            self.title_button.configure(text="YarWatch")
            self.logger.log("[Monitor] Watch stopped.")
        else:
            self.monitor.start()
            self.title_button.configure(text="Watching...")
            self.logger.log("[Monitor] Watch started.")

    def create_report(self):
        self.logger.log("Creating Report...")
        subprocess.run(["python", yar_report_script])

    def run_daily(self):
        self.logger.log("Running Daily Malware fetch...")
        subprocess.run(["python", daily_mal_script])

    def search(self):
        subprocess.run(["python", ioc_search_script])

    def cyberchef(self):
        webbrowser.open("https://cyberchef.io/")

    def thq(self):
        webbrowser.open("https://www.threathq.com/active-threat-reports")

    def dns_extractor(self):
        subprocess.run("DNSExtractor.exe")
