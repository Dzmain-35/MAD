import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import datetime
import json
import hashlib
import pefile
import threading
import psutil
import shutil
import queue
import time
from tkinter import ttk
from core.case_manager import CaseManager
from yarwatch.extractor import FeatureExtractor
from yarwatch.logger import YarLogger
from yarwatch.scanner import run_yara_file, run_yara_pid
from yarwatch.monitor import Monitor
from yarwatch.collapsible_frame import CollapsibleScanFrame 
from yarwatch.yarwatch_panel import YarWatchPanel
from PIL import Image

destination_path = "C:/Users/REM/Desktop/Case Data"
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

class MalwareDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("MAD - Malware Analysis Dashboard")
        self.geometry("1200x800")
        self.case_manager = CaseManager()
        
        # Track buttons and sections
        self.nav_buttons = {}
        self.sections = {}

        # Initialize persistent tabs
        self.analysis_tabview = None
        self.analysis_container = None
        self.active_tab = None

        self.setup_sidebar()
        self.show_section("New Case") 

    def update_attached_files_panel(self):
        if self.active_tab and isinstance(self.active_tab, ctk.CTkFrame):
            self.show_section("Current Case")

    def show_yarwatch_tab_embedded(self, parent_frame):
        output_queue = queue.Queue()
        logger = YarLogger(gui_queue=output_queue)
        extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
        monitor = Monitor(logger, extractor, self)

        yarwatch = YarWatchPanel(parent_frame, extractor, logger, output_queue, monitor,dashboard_gui=self)
        yarwatch.pack(fill="both", expand=True)

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

    def show_intro_tab(self):
        self.clear_main_area()
        frame = ctk.CTkFrame(self, fg_color="#0E2536")
        frame.pack(fill="both", expand=True)
        self.active_tab = frame

            # === Logo with red border ===
        logo_img = ctk.CTkImage(Image.open("core/image.png"), size=(250, 250))
        logo_border = ctk.CTkFrame(
    frame, 
    border_color="red", 
    border_width=3,
    fg_color="black", 
)
        logo_border.pack(pady=(30, 10))
        logo_label = ctk.CTkLabel(logo_border, image=logo_img, text="")
        logo_label.pack()

        ctk.CTkLabel(frame, text="New Malware Case", font=("Arial", 45, "bold"), text_color="white").pack(pady=(30, 10))
        ctk.CTkFrame(frame, height=2, fg_color="#cc0000").pack(fill="x", padx=120, pady=(5, 20))

        self.analyst_entry = ctk.CTkEntry(frame, placeholder_text="Enter Analyst Name", width=350, fg_color="#A30000", text_color="white",font=("Arial", 20, "bold"))
        self.analyst_entry.pack(pady=10)
        self.report_entry = ctk.CTkEntry(frame, placeholder_text="Enter Report URL", width=350, fg_color="#A30000", text_color="white",font=("Arial", 20, "bold"))
        self.report_entry.pack(pady=10)
        ctk.CTkButton(frame, text="Upload File to Start Case", command=self.handle_file_upload,width=45,height=45, fg_color="#A30000",hover_color="#800000").pack(pady=(20, 10))
    
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
        core_info = f"Analyst: {case['analyst']}\nReport URL: {case['report_url']}\nTimestamp: {case['timestamp']}\nStatus: {case['status']}"
        text_box.insert("1.0", core_info)
        text_box.configure(state="disabled")
        text_box.pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(frame, text="Attached Files:", font=("Arial", 22, "bold"), text_color="white").pack(pady=(10, 5))
        file_panel = ctk.CTkScrollableFrame(frame, fg_color="#102A3C")
        file_panel.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        for f in case.get("files", []):
            lines = ["File Details:", "="*66, f"File Name: {f.get('file_name')}", f"MD5: {f.get('md5', 'N/A')}",
                     f"SHA256: {f.get('sha256', 'N/A')}", f"File Size: {f.get('size', 'N/A')} bytes", "="*66,
                     f"IMPHASH: {f.get('imphash', 'N/A')}", f"YARA Rule: {f.get('rule', 'None')}",
                     f"VT Hits: {f.get('vt_hits', 0)}", f"THQ Family: {f.get('thq_family', 'None')}",
                     f"Threat Score: {f.get('threat_score', 0)} ({f.get('risk_level', 'Low')})", "="*66]
            if f.get("strings"):
                lines.append("YARA String Matches:")
                lines.extend([f"  - {s}" for s in f.get("strings", [])[:10]])
            CollapsibleFrame(file_panel, title=f.get("file_name", "Unknown File"), content=lines).pack(fill="x", pady=5, padx=5)
        ctk.CTkButton(frame, text="Attach File to Case",font=("Arial", 20, "bold"), command=self.attach_file_to_case, fg_color="#A30000").pack(pady=(5, 10))


        # Attach file option
    def show_analysis_tab(self):
        # If already built, just raise it
        if self.analysis_container:
            self.analysis_container.pack(fill="both", expand=True, padx=10, pady=10)
            self.active_tab = self.analysis_container
            return

        # Setup output pipeline
        self.analysis_output_queue = queue.Queue()
        self.analysis_logger = YarLogger(gui_queue=self.analysis_output_queue)
        self.analysis_feature_extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
        self.analysis_monitor = Monitor(self.analysis_logger, self.analysis_feature_extractor, self)

        # Outer container
        self.analysis_container = ctk.CTkFrame(self, fg_color="#0E2536")
        self.analysis_container.pack(fill="both", expand=True, padx=10, pady=10)
        self.active_tab = self.analysis_container

        # Tabview
        self.analysis_tabview = ctk.CTkTabview(self.analysis_container, corner_radius=8,fg_color="#0E2536")
        self.analysis_tabview.pack(fill="both", expand=True)

        # === YarWatch Tab (Live) ===
        if "YarWatch" not in self.analysis_tabview._tab_dict:
            yarwatch_tab = self.analysis_tabview.add("YarWatch")
            self.show_yarwatch_tab_embedded(yarwatch_tab)

        # === Placeholder Tabs ===
        placeholders = [
            ("Network", "DNS Extractor Tool Coming Soon"),
            ("CyberChef", "Machine Learning-based Threat Analysis Coming Soon"),
            ("OSINT", "Report Viewer Coming Soon")
        ]
        for tab_name, message in placeholders:
            if tab_name not in self.analysis_tabview._tab_dict:
                tab = self.analysis_tabview.add(tab_name)
                ctk.CTkLabel(
                    tab,
                    text=message,
                    text_color="#0E2536",
                    font=("Arial", 12, "italic")
                ).pack(pady=40)


    def show_section(self, section_name):
        self.clear_main_area()
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



    def handle_file_upload(self):
        analyst = self.analyst_entry.get().strip()
        report_url = self.report_entry.get().strip()
        if not analyst or not report_url:
            messagebox.showwarning("Missing Info", "Please fill in both fields before continuing.")
            return
        file_path = filedialog.askopenfilename(title="Select Malware Sample")
        if file_path:
            extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
            logger = YarLogger()
            run_yara_file(file_path, self, self, extractor, logger)
            with open("C:\\Users\\REM\\Desktop\\YarWatch_Log.json", "r") as f:
                entries = json.load(f)
                last = entries[-1] if entries else {}
            self.case_manager.add_case(analyst, report_url, last)
            shutil.copy(file_path,destination_path)
            messagebox.showinfo("Success", "Case successfully created and stored.")
            self.show_case_tab()

    def attach_file_to_case(self):
        file_path = filedialog.askopenfilename(title="Attach Additional File")
        if not file_path:
            return
        extractor = FeatureExtractor("C:\\Users\\REM\\Desktop\\Mal_Data")
        logger = YarLogger()
        run_yara_file(file_path,self, self, extractor, logger)
        with open("C:\\Users\\REM\\Desktop\\YarWatch_Log.json", "r") as f:
            entries = json.load(f)
            last = entries[-1] if entries else {}
        self.case_manager.add_file_to_case(last)
        messagebox.showinfo("Attached", "File successfully attached to case.")
        self.show_case_tab()
class CollapsibleFrame(ctk.CTkFrame):
    def __init__(self, master, title="Details", content=[], **kwargs):
        super().__init__(master, **kwargs)
        self.columnconfigure(0, weight=1)
        self.expanded = False

        self.header = ctk.CTkButton(self, text=title, command=self.toggle, fg_color="#004080",font=("Arial", 20, "bold"))
        self.header.grid(row=0, column=0, sticky="ew", padx=5, pady=2)

        self.content_frame = ctk.CTkFrame(self, fg_color="#102A3C")

        # Format nicely with newlines
        formatted = "\n".join(content)
        self.textbox = ctk.CTkTextbox(
            self.content_frame,
            wrap="word",
            font=("Consolas", 15),
            text_color="white",
            fg_color="#102A3C"
        )
        self.textbox.insert("1.0", formatted)
        self.textbox.configure(state="normal")  # allow copy
        self.textbox.pack(fill="both", expand=True, padx=10, pady=5)

    def toggle(self):
        if self.expanded:
            self.content_frame.grid_forget()
        else:
            self.content_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=(0, 5))
        self.expanded = not self.expanded



if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = MalwareDashboard()
    app.mainloop()
