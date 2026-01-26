
import customtkinter as ctk
from tkinter import filedialog, messagebox
from datetime import datetime
from case_manager import CaseManager
from PIL import Image
import os
import threading
import subprocess
import platform
import webbrowser
from analysis_modules.process_monitor import ProcessMonitor
from analysis_modules.network_monitor import NetworkMonitor
from analysis_modules.procmon_events import ProcmonLiveMonitor, ProcmonEvent
from analysis_modules.system_wide_monitor import SystemWideMonitor, EventFilter
from analysis_modules.sysmon_parser import SysmonLogMonitor
from analysis_modules.file_viewer_executor import get_viewer_executor
import tkinter as tk
from tkinter import ttk
import re
from typography import Fonts
from yara_rule_manager import YaraRuleManager
from settings_manager import SettingsManager

class ForensicAnalysisGUI:
    def __init__(self):
        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("MAD - Malware Analysis Dashboard")
        self.root.geometry("1200x800")
        
        # Color scheme
        self.colors = {
            "dark_blue": "#1a2332",
            "navy": "#0d1520",
            "red": "#dc2626",
            "red_dark": "#991b1b",
            "sidebar_bg": "#991b1b"
        }

        # Initialize settings manager first
        self.settings_manager = SettingsManager()
        print("Settings loaded successfully")

        # Get API keys from settings
        vt_api_key = self.settings_manager.get("api_keys.virustotal")
        threathq_user = self.settings_manager.get("api_keys.threathq_user")
        threathq_pass = self.settings_manager.get("api_keys.threathq_pass")

        # Initialize case manager with API keys from settings
        self.case_manager = CaseManager(
            vt_api_key=vt_api_key if vt_api_key else None,
            threathq_user=threathq_user if threathq_user else None,
            threathq_pass=threathq_pass if threathq_pass else None,
            settings_manager=self.settings_manager
        )
        print(f"Case storage initialized at: {self.case_manager.case_storage_path}")

        # Initialize YARA rule manager
        self.yara_rule_manager = YaraRuleManager(
            self.case_manager.yara_rules_path,
            settings_manager=self.settings_manager
        )

        # Data references
        self.current_case = None
        self.scan_in_progress = False
        self.cancel_scan = False
        self.progress_window = None

        # Initialize analysis modules
        self.process_monitor = ProcessMonitor(
            yara_rules_path=self.case_manager.yara_rules_path
        )

        self.network_monitor = NetworkMonitor()

        # Register callbacks for real-time updates
        self.process_monitor.register_process_callback(self.on_new_process_detected)
        self.network_monitor.register_connection_callback(self.on_new_connection_detected)

        # Monitoring states (from settings)
        self.process_monitor_active = False
        self.network_monitor_active = False

        # Auto-refresh state (from settings)
        self.auto_refresh_enabled = True
        self.auto_refresh_interval = self.settings_manager.get("application.auto_refresh_interval", 2000)
        self.auto_refresh_job = None
        self.pid_to_tree_item = {}  # Track PIDs to tree item IDs for incremental updates
        self.process_tree_initial_load = True  # Track if this is the first process list load

        # YARA popup limiting (from settings)
        self.popup_count_by_rule = {}  # Track popup count per YARA rule family
        self.max_popups_per_rule = self.settings_manager.get("application.max_popups_per_rule", 3)
        self.total_yara_matches = 0    # Total YARA matches for badge display

        # Procmon live monitors (PID -> monitor instance)
        self.procmon_monitors = {}

        # System-wide activity monitor
        self.system_wide_monitor = None
        self.system_monitor_active = False
        self.live_events_toggle_monitoring = None  # Will be set when tab is created

        # Create UI
        self.create_ui()
        
    def create_ui(self):
        """Build the main user interface"""
        self.create_header()
        self.create_main_container()
        
    def create_header(self):
        """Create top header bar"""
        header = ctk.CTkFrame(self.root, height=60, corner_radius=0, fg_color=self.colors["navy"])
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        
        title = ctk.CTkLabel(header, text="MAD - Malware Analysis Dashboard",
                            font=Fonts.header_subsection,
                            text_color="white")
        title.pack(side="left", padx=20, pady=15)
        
    def create_main_container(self):
        """Create main layout with sidebar and content area"""
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Create sidebar navigation
        self.create_sidebar(main_container)
        
        # Create content area
        self.content_area = ctk.CTkFrame(main_container, corner_radius=0)
        self.content_area.pack(side="right", fill="both", expand=True)
        
        # Create all tabs
        self.tabs = {}
        self.create_new_case_tab()
        self.create_current_case_tab()
        self.create_analysis_tab()
        self.create_yara_rules_tab()
        self.create_settings_tab()

        # Show initial tab
        self.show_tab("new_case")
        
    def create_sidebar(self, parent):
        """Create left sidebar with navigation buttons"""
        self.sidebar = ctk.CTkFrame(parent, width=200, corner_radius=0, fg_color=self.colors["sidebar_bg"])
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        nav_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_frame.pack(fill="both", expand=True, padx=10, pady=20)
        
        # Navigation buttons with updated styling
        self.btn_new_case = ctk.CTkButton(
            nav_frame, text="New Case", 
            command=lambda: self.show_tab("new_case"),
            height=45, font=Fonts.label_large,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            corner_radius=8
        )
        self.btn_new_case.pack(fill="x", pady=5)
        
        self.btn_current_case = ctk.CTkButton(
            nav_frame, text="Current Case",
            command=lambda: self.show_tab("current_case"),
            height=45, font=Fonts.label_large,
            fg_color="transparent", 
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            corner_radius=8
        )
        self.btn_current_case.pack(fill="x", pady=5)
        
        self.btn_analysis = ctk.CTkButton(
            nav_frame, text="Analysis",
            command=lambda: self.show_tab("analysis"),
            height=45, font=Fonts.label_large,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            corner_radius=8
        )
        self.btn_analysis.pack(fill="x", pady=5)

        self.btn_yara_rules = ctk.CTkButton(
            nav_frame, text="YARA Rules",
            command=lambda: self.show_tab("yara_rules"),
            height=45, font=Fonts.label_large,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            corner_radius=8
        )
        self.btn_yara_rules.pack(fill="x", pady=5)

        self.btn_settings = ctk.CTkButton(
            nav_frame, text="Settings",
            command=lambda: self.show_tab("settings"),
            height=45, font=Fonts.label_large,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            corner_radius=8
        )
        self.btn_settings.pack(fill="x", pady=5)
        
    # ==================== NEW CASE TAB ====================
    def create_new_case_tab(self):
        """Create the New Case tab interface with M.A.D. branding"""
        frame = ctk.CTkFrame(self.content_area, fg_color=self.colors["dark_blue"])
        
        # Center container
        center_container = ctk.CTkFrame(frame, fg_color="transparent")
        center_container.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo and branding section
        logo_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        logo_frame.pack(pady=(0, 30))
        
        # Load and display the M.A.D. logo image
        image_loaded = False
        try:
            # Try multiple possible locations for image.png
            possible_paths = [
                "image.png",
                os.path.join(os.getcwd(), "image.png"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "image.png"),
                os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "image.png"),
                r"C:\Users\REM\Desktop\MAD\image.png"
            ]
            
            logo_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    logo_path = path
                    break
            
            if logo_path and os.path.exists(logo_path):
                # Load and resize image
                pil_image = Image.open(logo_path)
                
                # Keep aspect ratio, max size 300px (smaller for form)
                max_size = 300
                pil_image.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)
                
                logo_image = ctk.CTkImage(
                    light_image=pil_image, 
                    dark_image=pil_image, 
                    size=(pil_image.width, pil_image.height)
                )
                
                logo_label = ctk.CTkLabel(
                    logo_frame,
                    image=logo_image,
                    text=""
                )
                logo_label.image = logo_image  # Keep a reference
                logo_label.pack()
                image_loaded = True
                
        except Exception as e:
            print(f"ERROR loading logo image: {e}")
        
        # Fallback to text-based logo if image not found
        if not image_loaded:
            self.create_fallback_logo(logo_frame)
        
        # Title section
        title_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        title_frame.pack(pady=(20, 20))
        
        title = ctk.CTkLabel(
            title_frame,
            text="New Malware Case",
            font=Fonts.header_main,
            text_color="white"
        )
        title.pack()
        
        # Separator line
        separator = ctk.CTkFrame(title_frame, height=3, fg_color=self.colors["red"])
        separator.pack(fill="x", pady=(10, 0))
        
        # Form container
        form_container = ctk.CTkFrame(center_container, fg_color="transparent")
        form_container.pack(pady=(20, 20))
        
        # Analyst Name input
        analyst_label = ctk.CTkLabel(
            form_container,
            text="Analyst Name",
            font=Fonts.label_large,
            text_color="white",
            anchor="w"
        )
        analyst_label.pack(anchor="w", padx=5, pady=(0, 5))
        
        self.analyst_name_entry = ctk.CTkEntry(
            form_container,
            width=400,
            height=40,
            placeholder_text="Enter your name",
            font=Fonts.body_large,
            fg_color=self.colors["navy"],
            border_color=self.colors["red"],
            border_width=2
        )
        self.analyst_name_entry.pack(padx=5, pady=(0, 15))
        
        # Report URL input
        report_label = ctk.CTkLabel(
            form_container,
            text="Report URL",
            font=Fonts.label_large,
            text_color="white",
            anchor="w"
        )
        report_label.pack(anchor="w", padx=5, pady=(0, 5))
        
        self.report_url_entry = ctk.CTkEntry(
            form_container,
            width=400,
            height=40,
            placeholder_text="Enter report URL",
            font=Fonts.body_large,
            fg_color=self.colors["navy"],
            border_color=self.colors["red"],
            border_width=2
        )
        self.report_url_entry.pack(padx=5, pady=(0, 20))

        # Upload method selection
        upload_method_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        upload_method_frame.pack(pady=(10, 10))

        method_label = ctk.CTkLabel(
            upload_method_frame,
            text="Select Upload Method:",
            font=Fonts.label_large,
            text_color="white"
        )
        method_label.pack(pady=(0, 10))

        # Radio button variable
        self.upload_method = tk.StringVar(value="file")

        radio_frame = ctk.CTkFrame(upload_method_frame, fg_color="transparent")
        radio_frame.pack()

        self.radio_file = ctk.CTkRadioButton(
            radio_frame,
            text="Upload Files",
            variable=self.upload_method,
            value="file",
            command=self.on_upload_method_change,
            font=Fonts.body_large,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.radio_file.pack(side="left", padx=20)

        self.radio_url = ctk.CTkRadioButton(
            radio_frame,
            text="Download from URLs",
            variable=self.upload_method,
            value="url",
            command=self.on_upload_method_change,
            font=Fonts.body_large,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.radio_url.pack(side="left", padx=20)

        # URL input area (initially hidden)
        self.url_input_frame = ctk.CTkFrame(center_container, fg_color=self.colors["navy"], corner_radius=8)

        url_input_label = ctk.CTkLabel(
            self.url_input_frame,
            text="Enter URLs (one per line):",
            font=Fonts.body_bold,
            text_color="white",
            anchor="w"
        )
        url_input_label.pack(anchor="w", padx=15, pady=(15, 5))

        self.url_input_textbox = tk.Text(
            self.url_input_frame,
            wrap="none",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.text_input(),
            relief="flat",
            padx=10,
            pady=10,
            height=6,
            width=48
        )
        self.url_input_textbox.pack(padx=15, pady=(0, 15))

        # Upload button
        btn_upload = ctk.CTkButton(
            center_container,
            text="Upload File to Start Case",
            command=self.handle_new_case_upload,
            height=50,
            width=400,
            font=Fonts.title_medium,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            corner_radius=8
        )
        btn_upload.pack(pady=(10, 10))
        self.btn_new_case_upload = btn_upload
        
        # Status label for feedback
        self.new_case_status = ctk.CTkLabel(
            center_container,
            text="",
            font=Fonts.body,
            text_color="white"
        )
        self.new_case_status.pack(pady=10)
        
        self.tabs["new_case"] = frame
    
    def create_fallback_logo(self, parent_frame):
        """Create fallback text-based logo if image.png is not found"""
        logo_shield = ctk.CTkLabel(
            parent_frame,
            text="🛡",
            font=Fonts.logo_emoji,
            text_color=self.colors["red"]
        )
        logo_shield.pack(side="left", padx=(0, 20))
        
        logo_text_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        logo_text_frame.pack(side="left")
        
        logo_main = ctk.CTkLabel(
            logo_text_frame,
            text="M.A.D.",
            font=Fonts.logo_main,
            text_color="white"
        )
        logo_main.pack(anchor="w")
        
        logo_subtitle = ctk.CTkLabel(
            logo_text_frame,
            text="MALWARE ANALYSIS\nDASHBOARD",
            font=Fonts.logo_subtitle,
            text_color="white",
            justify="left"
        )
        logo_subtitle.pack(anchor="w")
        
    # ==================== CURRENT CASE TAB ====================
    def create_current_case_tab(self):
        """Create the Current Case tab interface"""
        frame = ctk.CTkFrame(self.content_area, fg_color=self.colors["dark_blue"])
        
        # Header with title and status
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=10, padx=20)
        
        title = ctk.CTkLabel(header_frame, text="Current Case",
                            font=Fonts.header_section,
                            text_color="white")
        title.pack(side="left")
        
        self.case_status_label = ctk.CTkLabel(header_frame, text="",
                                             corner_radius=20,
                                             fg_color="#2D7A3E",
                                             width=100, height=30,
                                             text_color="white",
                                             font=Fonts.label)
        self.case_status_label.pack(side="right", padx=10)
        
        # Scrollable frame for content
        scroll_frame = ctk.CTkScrollableFrame(frame, corner_radius=10, fg_color=self.colors["navy"])
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        
        # Case details card - COMPACT VERSION
        self.case_details_frame = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20")
        self.case_details_frame.pack(fill="x", pady=5)
        
        details_title = ctk.CTkLabel(self.case_details_frame, text="Case Details",
                                    font=Fonts.title_medium,
                                    text_color="white")
        details_title.pack(pady=10, padx=15, anchor="w")
        
        self.case_info_frame = ctk.CTkFrame(self.case_details_frame, 
                                           fg_color="transparent")
        self.case_info_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        # Files section header - Clickable
        files_header = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20", cursor="hand2")
        files_header.pack(fill="x", pady=(10, 5))

        files_header_inner = ctk.CTkFrame(files_header, fg_color="transparent", cursor="hand2")
        files_header_inner.pack(fill="x", padx=15, pady=10)

        # Expand indicator for files
        self.files_expand_indicator = ctk.CTkLabel(files_header_inner, text="▼",
                                                   font=Fonts.body_large,
                                                   text_color="gray60",
                                                   cursor="hand2")
        self.files_expand_indicator.pack(side="left", padx=(0, 10))

        files_title = ctk.CTkLabel(files_header_inner, text="Uploaded Files",
                                  font=Fonts.title_medium,
                                  text_color="white",
                                  cursor="hand2")
        files_title.pack(side="left")

        btn_add_files = ctk.CTkButton(files_header_inner, text="➕ Add Files",
                                     command=self.handle_add_files,
                                     height=30, width=100,
                                     fg_color=self.colors["red"],
                                     hover_color=self.colors["red_dark"],
                                     font=Fonts.label)
        btn_add_files.pack(side="right")

        # Files list container (collapsible)
        self.files_list_frame = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="transparent")
        self.files_list_frame.pack(fill="x", pady=(0, 10))

        # IOCs section header - Clickable
        iocs_header = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20", cursor="hand2")
        iocs_header.pack(fill="x", pady=(10, 5))

        iocs_header_inner = ctk.CTkFrame(iocs_header, fg_color="transparent", cursor="hand2")
        iocs_header_inner.pack(fill="x", padx=15, pady=10)

        # Expand indicator for IOCs
        self.iocs_expand_indicator = ctk.CTkLabel(iocs_header_inner, text="▼",
                                                  font=Fonts.body_large,
                                                  text_color="gray60",
                                                  cursor="hand2")
        self.iocs_expand_indicator.pack(side="left", padx=(0, 10))

        iocs_title = ctk.CTkLabel(iocs_header_inner, text="Indicators of Compromise (IOCs)",
                                  font=Fonts.title_medium,
                                  text_color="white",
                                  cursor="hand2")
        iocs_title.pack(side="left")

        btn_add_ioc = ctk.CTkButton(iocs_header_inner, text="➕ Add IOC",
                                    command=self.handle_add_ioc,
                                    height=30, width=100,
                                    fg_color=self.colors["red"],
                                    hover_color=self.colors["red_dark"],
                                    font=Fonts.label)
        btn_add_ioc.pack(side="right")

        # IOCs container (collapsible)
        iocs_container = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20")
        iocs_container.pack(fill="x", pady=(0, 10))

        # IOCs content frame
        self.iocs_content_frame = ctk.CTkFrame(iocs_container, fg_color="transparent")
        self.iocs_content_frame.pack(fill="both", expand=True, padx=15, pady=15)

        # Notes section header - Clickable
        notes_header = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20", cursor="hand2")
        notes_header.pack(fill="x", pady=(10, 5))

        notes_header_inner = ctk.CTkFrame(notes_header, fg_color="transparent", cursor="hand2")
        notes_header_inner.pack(fill="x", padx=15, pady=10)

        # Expand indicator for Notes
        self.notes_expand_indicator = ctk.CTkLabel(notes_header_inner, text="▼",
                                                   font=Fonts.body_large,
                                                   text_color="gray60",
                                                   cursor="hand2")
        self.notes_expand_indicator.pack(side="left", padx=(0, 10))

        notes_title = ctk.CTkLabel(notes_header_inner, text="Case Notes",
                                  font=Fonts.title_medium,
                                  text_color="white",
                                  cursor="hand2")
        notes_title.pack(side="left")

        # Save notes button
        btn_save_notes = ctk.CTkButton(notes_header_inner, text="💾 Save Notes",
                                      command=self.handle_save_notes,
                                      height=30, width=100,
                                      fg_color=self.colors["red"],
                                      hover_color=self.colors["red_dark"],
                                      font=Fonts.label)
        btn_save_notes.pack(side="right")

        # Notes text area (collapsible)
        notes_container = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20")
        notes_container.pack(fill="both", expand=True, pady=(0, 10))

        # Track visibility states
        self.files_section_visible = [True]
        self.iocs_section_visible = [True]
        self.notes_section_visible = [True]

        # Toggle function for files section
        def toggle_files_section(event=None):
            # Prevent toggle when clicking the Add Files button
            if event and hasattr(event.widget, 'cget'):
                try:
                    if event.widget.cget('text') == "➕ Add Files":
                        return
                except:
                    pass

            if self.files_section_visible[0]:
                self.files_list_frame.pack_forget()
                self.files_expand_indicator.configure(text="▶")
                self.files_section_visible[0] = False
            else:
                # Re-pack before the IOCs header to maintain position
                self.files_list_frame.pack(fill="x", pady=(0, 10), before=iocs_header)
                self.files_expand_indicator.configure(text="▼")
                self.files_section_visible[0] = True

        # Toggle function for IOCs section
        def toggle_iocs_section(event=None):
            # Prevent toggle when clicking the Add IOC button
            if event and hasattr(event.widget, 'cget'):
                try:
                    if event.widget.cget('text') == "➕ Add IOC":
                        return
                except:
                    pass

            if self.iocs_section_visible[0]:
                iocs_container.pack_forget()
                self.iocs_expand_indicator.configure(text="▶")
                self.iocs_section_visible[0] = False
            else:
                # Re-pack before the Notes header to maintain position
                iocs_container.pack(fill="x", pady=(0, 10), before=notes_header)
                self.iocs_expand_indicator.configure(text="▼")
                self.iocs_section_visible[0] = True

        # Toggle function for Notes section
        def toggle_notes_section(event=None):
            # Prevent toggle when clicking the Save Notes button
            if event and hasattr(event.widget, 'cget'):
                try:
                    if event.widget.cget('text') == "💾 Save Notes":
                        return
                except:
                    pass

            if self.notes_section_visible[0]:
                notes_container.pack_forget()
                self.notes_expand_indicator.configure(text="▶")
                self.notes_section_visible[0] = False
            else:
                # Re-pack at end
                notes_container.pack(fill="both", expand=True, pady=(0, 10))
                self.notes_expand_indicator.configure(text="▼")
                self.notes_section_visible[0] = True

        # Bind click events for files section
        files_header.bind("<Button-1>", toggle_files_section)
        files_header_inner.bind("<Button-1>", toggle_files_section)
        files_title.bind("<Button-1>", toggle_files_section)
        self.files_expand_indicator.bind("<Button-1>", toggle_files_section)

        # Bind click events for IOCs section
        iocs_header.bind("<Button-1>", toggle_iocs_section)
        iocs_header_inner.bind("<Button-1>", toggle_iocs_section)
        iocs_title.bind("<Button-1>", toggle_iocs_section)
        self.iocs_expand_indicator.bind("<Button-1>", toggle_iocs_section)

        # Bind click events for Notes section
        notes_header.bind("<Button-1>", toggle_notes_section)
        notes_header_inner.bind("<Button-1>", toggle_notes_section)
        notes_title.bind("<Button-1>", toggle_notes_section)
        self.notes_expand_indicator.bind("<Button-1>", toggle_notes_section)

        # IOCs lists
        self.iocs_urls_frame = ctk.CTkFrame(self.iocs_content_frame, fg_color="#1a1a1a", corner_radius=5)
        self.iocs_urls_frame.pack(fill="x", pady=(0, 10))

        urls_label = ctk.CTkLabel(self.iocs_urls_frame, text="URLs:",
                                  font=Fonts.body_bold,
                                  text_color="white", anchor="w")
        urls_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_urls_list = ctk.CTkTextbox(self.iocs_urls_frame, height=80,
                                             fg_color="#0d1520", corner_radius=5)
        self.iocs_urls_list.pack(fill="x", padx=10, pady=(0, 10))

        self.iocs_ips_frame = ctk.CTkFrame(self.iocs_content_frame, fg_color="#1a1a1a", corner_radius=5)
        self.iocs_ips_frame.pack(fill="x", pady=(0, 10))

        ips_label = ctk.CTkLabel(self.iocs_ips_frame, text="IP Addresses:",
                                 font=Fonts.body_bold,
                                 text_color="white", anchor="w")
        ips_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_ips_list = ctk.CTkTextbox(self.iocs_ips_frame, height=80,
                                            fg_color="#0d1520", corner_radius=5)
        self.iocs_ips_list.pack(fill="x", padx=10, pady=(0, 10))

        self.iocs_domains_frame = ctk.CTkFrame(self.iocs_content_frame, fg_color="#1a1a1a", corner_radius=5)
        self.iocs_domains_frame.pack(fill="x", pady=(0, 10))

        domains_label = ctk.CTkLabel(self.iocs_domains_frame, text="Domains:",
                                     font=Fonts.body_bold,
                                     text_color="white", anchor="w")
        domains_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_domains_list = ctk.CTkTextbox(self.iocs_domains_frame, height=80,
                                                fg_color="#0d1520", corner_radius=5)
        self.iocs_domains_list.pack(fill="x", padx=10, pady=(0, 10))

        # Notes text widget
        self.notes_textbox = tk.Text(
            notes_container,
            wrap="word",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.text_input(),
            relief="flat",
            padx=15,
            pady=15,
            height=8
        )
        self.notes_textbox.pack(fill="both", expand=True, padx=2, pady=2)
        
        self.tabs["current_case"] = frame
        
    # ==================== ANALYSIS TAB ====================
    def create_analysis_tab(self):
        """Create the Analysis tab with sub-tabs"""
        frame = ctk.CTkFrame(self.content_area, fg_color=self.colors["dark_blue"])
        
        title = ctk.CTkLabel(frame, text="Analysis",
                            font=Fonts.header_main,
                            text_color="white")
        title.pack(pady=20, padx=20, anchor="w")
        
        # Sub-tab buttons
        subtab_frame = ctk.CTkFrame(frame, fg_color="transparent")
        subtab_frame.pack(fill="x", padx=20, pady=10)
        
        self.btn_processes = ctk.CTkButton(
            subtab_frame, text="⚙️ Processes",
            command=lambda: self.show_analysis_subtab("processes"),
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.body_bold
        )
        self.btn_processes.pack(side="left", padx=5)
        
        self.btn_network = ctk.CTkButton(
            subtab_frame, text="🌐 Network",
            command=lambda: self.show_analysis_subtab("network"),
            height=35, width=150,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"],
            font=Fonts.body_bold
        )
        self.btn_network.pack(side="left", padx=5)

        self.btn_live_events = ctk.CTkButton(
            subtab_frame, text="📡 Live Events",
            command=lambda: self.show_analysis_subtab("live_events"),
            height=35, width=150,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"],
            font=Fonts.body_bold
        )
        self.btn_live_events.pack(side="left", padx=5)

        # Content area for sub-tabs
        self.analysis_content = ctk.CTkFrame(frame, corner_radius=10, fg_color=self.colors["navy"])
        self.analysis_content.pack(fill="both", expand=True, padx=20, pady=10)

        # Create sub-tab frames
        self.analysis_subtabs = {}
        self.create_processes_subtab()
        self.create_network_subtab()
        self.create_live_events_subtab()
        
        self.tabs["analysis"] = frame
        self.show_analysis_subtab("processes")
        
    def create_processes_subtab(self):
        """Create Processes sub-tab with optimized tree view"""
        frame = ctk.CTkFrame(self.analysis_content, fg_color="transparent")
        
        # Header with controls
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)
        
        title = ctk.CTkLabel(header, text="Process Analysis",
                            font=Fonts.title_large,
                            text_color="white")
        title.pack(side="left")
        
        # Monitor toggle
        self.btn_toggle_process_monitor = ctk.CTkButton(
            header, text="▶ Start Monitoring",
            command=self.toggle_process_monitoring,
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.btn_toggle_process_monitor.pack(side="right", padx=5)

        # Scan All button
        btn_scan_all = ctk.CTkButton(
            header, text="🔍 Scan All",
            command=self.scan_all_processes,
            height=35, width=100,
            fg_color="#8B4513",
            hover_color="#A0522D"
        )
        btn_scan_all.pack(side="right", padx=5)

        # Refresh button
        btn_refresh = ctk.CTkButton(
            header, text="🔄 Refresh",
            command=self.refresh_process_list,
            height=35, width=100,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"]
        )
        btn_refresh.pack(side="right", padx=5)

        # Search bar
        search_frame = ctk.CTkFrame(frame, fg_color="transparent")
        search_frame.pack(fill="x", padx=20, pady=(0, 10))

        search_label = ctk.CTkLabel(search_frame, text="🔍 Search:",
                                   font=Fonts.body,
                                   text_color="white")
        search_label.pack(side="left", padx=(0, 10))

        self.process_search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Enter PID or Process Name...",
            height=35,
            width=300,
            fg_color="gray20",
            border_color=self.colors["navy"],
            border_width=2
        )
        self.process_search_entry.pack(side="left", padx=5)
        self.process_search_entry.bind("<KeyRelease>", lambda e: self.filter_processes())

        # Clear search button
        btn_clear_search = ctk.CTkButton(
            search_frame, text="✕ Clear",
            command=self.clear_process_search,
            height=35, width=80,
            fg_color="gray30",
            hover_color="gray40"
        )
        btn_clear_search.pack(side="left", padx=5)

        # Filter dropdown
        filter_label = ctk.CTkLabel(search_frame, text="Filter:",
                                    font=Fonts.body,
                                    text_color="white")
        filter_label.pack(side="left", padx=(20, 10))

        self.process_filter_var = ctk.StringVar(value="All Processes")
        self.process_filter_dropdown = ctk.CTkComboBox(
            search_frame,
            values=["All Processes", "YARA Matches Only", "Benign Only", "Not Scanned"],
            variable=self.process_filter_var,
            command=lambda choice: self.filter_processes(),
            height=35,
            width=180,
            fg_color="gray20",
            border_color=self.colors["navy"],
            button_color=self.colors["navy"],
            button_hover_color=self.colors["dark_blue"]
        )
        self.process_filter_dropdown.pack(side="left", padx=5)

        # YARA match counter badge
        self.yara_match_badge = ctk.CTkLabel(
            search_frame,
            text="⚠️ YARA: 0",
            font=("Segoe UI", 13, "bold"),
            text_color="#fbbf24",  # Amber color
            fg_color="#78350f",     # Dark amber background
            corner_radius=6,
            padx=12,
            pady=6
        )
        self.yara_match_badge.pack(side="left", padx=(15, 5))

        # Process tree area with parent-child hierarchy
        tree_frame = ctk.CTkFrame(frame, fg_color="gray20")
        tree_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Scrollbars
        vsb = tk.Scrollbar(tree_frame, orient="vertical", bg="#1a1a1a", troughcolor="#0d1520")
        hsb = tk.Scrollbar(tree_frame, orient="horizontal", bg="#1a1a1a", troughcolor="#0d1520")
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        
        # Style for Treeview to match dark theme
        style = ttk.Style()
        style.theme_use('default')
        
        # Configure Treeview colors
        style.configure("Process.Treeview",
                       background="#1a1a1a",
                       foreground="white",
                       fieldbackground="#1a1a1a",
                       borderwidth=0,
                       relief="flat")
        
        style.configure("Process.Treeview.Heading",
                       background="#0d1520",
                       foreground="white",
                       borderwidth=1,
                       relief="flat")
        
        style.map("Process.Treeview",
                 background=[('selected', '#dc2626')],
                 foreground=[('selected', 'white')])
        
        style.map("Process.Treeview.Heading",
                 background=[('active', '#1a2332')])
        
        # Treeview with hierarchy support
        columns = ("PID", "Name", "File Path", "YARA Matches")
        self.process_tree = ttk.Treeview(
            tree_frame, 
            columns=columns, 
            show="tree headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            style="Process.Treeview"
        )
        self.process_tree.pack(side="left", fill="both", expand=True)
        vsb.config(command=self.process_tree.yview)
        hsb.config(command=self.process_tree.xview)
        
        # Configure columns
        self.process_tree.column("#0", width=200, minwidth=150)  # Tree hierarchy
        self.process_tree.column("PID", width=80, minwidth=60, anchor="center")
        self.process_tree.column("Name", width=200, minwidth=150)
        self.process_tree.column("File Path", width=350, minwidth=200)
        self.process_tree.column("YARA Matches", width=150, minwidth=100, anchor="center")
        
        # Headers
        self.process_tree.heading("#0", text="Process Tree")
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Name")
        self.process_tree.heading("File Path", text="File Path")
        self.process_tree.heading("YARA Matches", text="YARA Matches")
        
        # Right-click menu with dark theme styling
        self.process_context_menu = tk.Menu(
            self.process_tree, 
            tearoff=0,
            bg="#1a1a1a",
            fg="white",
            activebackground="#dc2626",
            activeforeground="white",
            borderwidth=0,
            relief="flat"
        )
        self.process_context_menu.add_command(
            label="🔍 Scan with YARA", 
            command=self.scan_selected_process
        )
        self.process_context_menu.add_command(
            label="📋 View Details & Strings",  # FIXED: Combined command
            command=self.view_process_details_and_strings
        )
        self.process_context_menu.add_command(
            label="📂 Open Folder Location",
            command=self.open_folder_location
        )
        self.process_context_menu.add_separator(background="#444444")
        # Note: Suspend/Resume will be added dynamically in show_process_context_menu
        self.process_context_menu.add_command(
            label="❌ Kill Process",
            command=self.kill_selected_process
        )
        
        self.process_tree.bind("<Button-3>", self.show_process_context_menu)
        self.process_tree.bind("<Double-1>", lambda e: self.view_process_details_and_strings())  # FIXED
        
        # Configure tag colors
        self.process_tree.tag_configure('threat', background='#5c1c1c', foreground='white')
        self.process_tree.tag_configure('new', background='#8B7500', foreground='white')  # Gold for new processes
        self.process_tree.tag_configure('benign', background='#1a4d2e', foreground='white')  # Green for whitelisted/benign
        self.process_tree.tag_configure('system', foreground='#888888')
        self.process_tree.tag_configure('suspended', background='#3a3a3a', foreground='#808080')  # Grey for suspended processes
        
        self.analysis_subtabs["processes"] = frame
        
        # Initial load
        self.refresh_process_list()
        
    def create_network_subtab(self):
        """Create Network sub-tab"""
        frame = ctk.CTkFrame(self.analysis_content, fg_color="transparent")
        
        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)
        
        title = ctk.CTkLabel(header, text="Network Analysis",
                            font=Fonts.title_large,
                            text_color="white")
        title.pack(side="left")
        
        # Monitor toggle
        self.btn_toggle_network_monitor = ctk.CTkButton(
            header, text="▶ Start Monitoring",
            command=self.toggle_network_monitoring,
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.btn_toggle_network_monitor.pack(side="right", padx=5)
        
        # Refresh button
        btn_refresh = ctk.CTkButton(
            header, text="🔄 Refresh",
            command=self.refresh_network_list,
            height=35, width=100,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"]
        )
        btn_refresh.pack(side="right", padx=5)
        
        # Stats frame
        stats_frame = ctk.CTkFrame(frame, fg_color="gray20", corner_radius=10)
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        self.network_stats_label = ctk.CTkLabel(
            stats_frame,
            text="Network Statistics: Not monitoring",
            font=Fonts.helper,
            justify="left"
        )
        self.network_stats_label.pack(padx=15, pady=10, anchor="w")
        
        # Connection list
        tree_frame = ctk.CTkFrame(frame, fg_color="gray20")
        tree_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        vsb = tk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side="right", fill="y")

        columns = ("Type", "Local", "Remote", "Hostname", "Status", "Process", "Suspicious")
        self.network_tree = ttk.Treeview(tree_frame, columns=columns,
                                        show="headings", yscrollcommand=vsb.set)
        self.network_tree.pack(side="left", fill="both", expand=True)
        vsb.config(command=self.network_tree.yview)

        # Configure columns with specific widths
        self.network_tree.heading("Type", text="Type")
        self.network_tree.column("Type", width=80, minwidth=60)
        self.network_tree.heading("Local", text="Local")
        self.network_tree.column("Local", width=150, minwidth=100)
        self.network_tree.heading("Remote", text="Remote")
        self.network_tree.column("Remote", width=150, minwidth=100)
        self.network_tree.heading("Hostname", text="Hostname")
        self.network_tree.column("Hostname", width=200, minwidth=120)
        self.network_tree.heading("Status", text="Status")
        self.network_tree.column("Status", width=100, minwidth=80)
        self.network_tree.heading("Process", text="Process")
        self.network_tree.column("Process", width=150, minwidth=100)
        self.network_tree.heading("Suspicious", text="Suspicious")
        self.network_tree.column("Suspicious", width=80, minwidth=60)

        # Configure tag colors
        self.network_tree.tag_configure('suspicious', background='#5c1c1c')

        # Right-click context menu for network tree
        self.network_context_menu = tk.Menu(
            self.network_tree,
            tearoff=0,
            bg="#1a1a1a",
            fg="white",
            activebackground="#dc2626",
            activeforeground="white",
            borderwidth=0,
            relief="flat"
        )
        self.network_context_menu.add_command(
            label="📋 Copy Local Address",
            command=lambda: self.copy_network_cell(1)
        )
        self.network_context_menu.add_command(
            label="📋 Copy Remote Address",
            command=lambda: self.copy_network_cell(2)
        )
        self.network_context_menu.add_command(
            label="📋 Copy Hostname",
            command=lambda: self.copy_network_cell(3)
        )
        self.network_context_menu.add_command(
            label="📋 Copy Process Name",
            command=lambda: self.copy_network_cell(5)
        )
        self.network_context_menu.add_separator(background="#444444")
        self.network_context_menu.add_command(
            label="📋 Copy Entire Row",
            command=self.copy_network_row
        )
        self.network_context_menu.add_separator(background="#444444")
        self.network_context_menu.add_command(
            label="➕ Add Remote IP to IOCs",
            command=lambda: self.add_network_ioc_to_case("remote_ip")
        )
        self.network_context_menu.add_command(
            label="➕ Add Hostname to IOCs",
            command=lambda: self.add_network_ioc_to_case("hostname")
        )

        self.network_tree.bind("<Button-3>", self.show_network_context_menu)

        self.analysis_subtabs["network"] = frame

    # ==================== LIVE EVENTS SUBTAB ====================
    def create_live_events_subtab(self):
        """Create the Live Events subtab for system-wide monitoring"""
        frame = ctk.CTkFrame(self.analysis_content, fg_color="transparent")

        # Header with title
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)

        title = ctk.CTkLabel(header, text="Live System Events",
                            font=Fonts.title_large,
                            text_color="white")
        title.pack(side="left")

        subtitle = ctk.CTkLabel(header,
                               text="Real-time monitoring: File • Registry • Network • Process • DNS",
                               font=Fonts.helper, text_color="gray60")
        subtitle.pack(side="left", padx=20)

        # Main content area
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # ===== CONTROL PANEL =====
        control_panel = ctk.CTkFrame(content, fg_color=self.colors["navy"], height=120)
        control_panel.pack(fill="x", pady=(0, 10))
        control_panel.pack_propagate(False)

        # Row 1: Start/Stop and Status
        row1 = ctk.CTkFrame(control_panel, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(10, 5))

        # Start/Stop button
        monitor_btn_text = tk.StringVar(value="▶ Start Monitoring")
        monitor_btn = ctk.CTkButton(
            row1,
            textvariable=monitor_btn_text,
            command=None,  # Will be set later
            height=40,
            width=180,
            font=Fonts.label_large,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        monitor_btn.pack(side="left", padx=(0, 20))

        # Status label
        status_label = ctk.CTkLabel(
            row1,
            text="● Monitoring: Stopped",
            font=Fonts.body_large,
            text_color="gray50"
        )
        status_label.pack(side="left", padx=10)

        # Sysmon status
        sysmon_status = ctk.CTkLabel(
            row1,
            text="",
            font=Fonts.helper,
            text_color="gray60"
        )
        sysmon_status.pack(side="left", padx=10)

        # Export and Clear buttons
        export_btn = ctk.CTkButton(
            row1,
            text="💾 Export CSV",
            command=None,  # Will be set later
            height=35,
            width=120,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        export_btn.pack(side="right", padx=5)

        clear_btn = ctk.CTkButton(
            row1,
            text="🗑 Clear Events",
            command=None,  # Will be set later
            height=35,
            width=120,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        clear_btn.pack(side="right", padx=5)

        # Row 2: Statistics
        row2 = ctk.CTkFrame(control_panel, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=5)

        stats_label = ctk.CTkLabel(
            row2,
            text="Total: 0 | File: 0 | Registry: 0 | Network: 0 | Process: 0 | DNS: 0",
            font=Fonts.body,
            text_color="gray60"
        )
        stats_label.pack(side="left")

        # ===== FILTER PANEL =====
        filter_panel = ctk.CTkFrame(content, fg_color=self.colors["navy"])
        filter_panel.pack(fill="x", pady=(0, 10))

        # Filter row 1: Event types
        filter_row1 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        filter_row1.pack(fill="x", padx=10, pady=(10, 5))

        filter_label1 = ctk.CTkLabel(
            filter_row1,
            text="Event Type:",
            font=Fonts.body_bold
        )
        filter_label1.pack(side="left", padx=(0, 10))

        # Event type filter buttons
        filter_types = ["All", "File", "Registry", "Network", "Process", "Thread", "DNS"]
        event_type_buttons = {}

        for ftype in filter_types:
            btn = ctk.CTkButton(
                filter_row1,
                text=ftype,
                command=None,  # Will be set later
                height=30,
                width=85,
                fg_color=self.colors["red"] if ftype == "All" else "transparent",
                hover_color=self.colors["navy"],
                border_width=1,
                border_color=self.colors["red"]
            )
            btn.pack(side="left", padx=3)
            event_type_buttons[ftype] = btn

        # Suspicious only toggle
        suspicious_var = tk.BooleanVar(value=False)
        suspicious_check = ctk.CTkCheckBox(
            filter_row1,
            text="🚨 Suspicious Only",
            variable=suspicious_var,
            command=None,  # Will be set later
            font=Fonts.body_bold,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        suspicious_check.pack(side="right", padx=10)

        # Filter row 2: PID and regex
        filter_row2 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        filter_row2.pack(fill="x", padx=10, pady=(5, 10))

        # PID filter
        pid_filter_label = ctk.CTkLabel(
            filter_row2,
            text="PID Filter:",
            font=Fonts.helper
        )
        pid_filter_label.pack(side="left", padx=(0, 5))

        pid_filter_entry = ctk.CTkEntry(
            filter_row2,
            placeholder_text="Enter PID (optional)",
            width=150,
            height=30
        )
        pid_filter_entry.pack(side="left", padx=5)

        # Include child processes checkbox
        include_children_var = tk.BooleanVar(value=False)
        include_children_checkbox = ctk.CTkCheckBox(
            filter_row2,
            text="Include children",
            variable=include_children_var,
            font=Fonts.helper,
            width=120
        )
        include_children_checkbox.pack(side="left", padx=5)

        # Path regex filter
        regex_filter_label = ctk.CTkLabel(
            filter_row2,
            text="Path Regex:",
            font=Fonts.helper
        )
        regex_filter_label.pack(side="left", padx=(20, 5))

        regex_filter_entry = ctk.CTkEntry(
            filter_row2,
            placeholder_text="Enter regex pattern (e.g., .*\\Run\\.*)",
            width=300,
            height=30
        )
        regex_filter_entry.pack(side="left", padx=5)

        apply_filter_btn = ctk.CTkButton(
            filter_row2,
            text="Apply Filters",
            command=None,  # Will be set later
            height=30,
            width=100,
            fg_color=self.colors["red"]
        )
        apply_filter_btn.pack(side="left", padx=10)

        clear_filter_btn = ctk.CTkButton(
            filter_row2,
            text="Clear Filters",
            command=None,  # Will be set later
            height=30,
            width=100,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        clear_filter_btn.pack(side="left", padx=5)

        # ===== PROCESS INFO PANEL (Procmon-style, shown when PID filter active) =====
        process_info_panel = ctk.CTkFrame(content, fg_color=self.colors["dark_blue"], height=80)
        process_info_label = ctk.CTkLabel(
            process_info_panel,
            text="",
            font=Fonts.helper,
            text_color="white",
            anchor="w",
            justify="left"
        )
        process_info_label.pack(fill="both", expand=True, padx=15, pady=10)

        # ===== EVENTS DISPLAY =====
        events_frame = ctk.CTkFrame(content, fg_color="gray20")
        events_frame.pack(fill="both", expand=True)

        # Scrollbars
        events_vsb = tk.Scrollbar(events_frame, orient="vertical", bg="#1a1a1a")
        events_vsb.pack(side="right", fill="y")

        events_hsb = tk.Scrollbar(events_frame, orient="horizontal", bg="#1a1a1a")
        events_hsb.pack(side="bottom", fill="x")

        # TreeView for events
        columns = ("time", "pid", "process", "type", "operation", "path", "result")
        events_tree = ttk.Treeview(
            events_frame,
            columns=columns,
            show="headings",
            height=25,
            yscrollcommand=events_vsb.set,
            xscrollcommand=events_hsb.set
        )

        # Configure columns
        events_tree.heading("time", text="Time")
        events_tree.heading("pid", text="PID")
        events_tree.heading("process", text="Process")
        events_tree.heading("type", text="Type")
        events_tree.heading("operation", text="Operation")
        events_tree.heading("path", text="Path / Target")
        events_tree.heading("result", text="Result")

        events_tree.column("time", width=100, minwidth=100)
        events_tree.column("pid", width=60, minwidth=60)
        events_tree.column("process", width=120, minwidth=100)
        events_tree.column("type", width=80, minwidth=80)
        events_tree.column("operation", width=150, minwidth=120)
        events_tree.column("path", width=400, minwidth=200)
        events_tree.column("result", width=100, minwidth=80)

        # Style the tree
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                       background="#1a1a1a",
                       foreground="white",
                       fieldbackground="#1a1a1a",
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background="#0d1520",
                       foreground="white",
                       borderwidth=1)
        style.map("Treeview",
                 background=[("selected", "#dc2626")])

        # Tag for suspicious events
        events_tree.tag_configure('suspicious', background='#5c1c1c', foreground='#ff6b6b')

        events_tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        events_vsb.config(command=events_tree.yview)
        events_hsb.config(command=events_tree.xview)

        # Context menu for events
        events_context_menu = tk.Menu(events_tree, tearoff=0, bg='#1a1a1a', fg='white',
                                      activebackground=self.colors["red"])
        events_context_menu.add_command(label="🔍 Focus on PID", command=None)  # Will be set
        events_context_menu.add_command(label="📋 Copy Path", command=None)  # Will be set
        events_context_menu.add_separator()
        events_context_menu.add_command(label="➕ Extract IOCs to Case", command=lambda: self.add_live_event_iocs_to_case(events_tree))
        events_context_menu.add_separator()
        events_context_menu.add_command(label="🗑 Remove Event", command=None)  # Will be set

        def show_context_menu(event):
            try:
                events_context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                events_context_menu.grab_release()

        events_tree.bind("<Button-3>", show_context_menu)

        # Store state for monitoring
        from datetime import timedelta
        monitor_state = {
            "monitor": None,
            "monitoring": False,
            "current_filter": None,
            "update_job": None,
            "last_update_time": datetime.now() - timedelta(days=1),  # Start from yesterday to catch existing events
            "event_count": 0
        }

        # ===== MONITOR FUNCTIONS =====
        def toggle_monitoring():
            """Start/stop system-wide monitoring"""
            if not monitor_state["monitoring"]:
                # Start monitoring
                try:
                    # Create system-wide monitor
                    monitor = SystemWideMonitor(max_events=50000)

                    # Check if Sysmon is available
                    sysmon_available = False
                    try:
                        sysmon_test = SysmonLogMonitor()
                        sysmon_available = sysmon_test.is_available()
                    except:
                        pass

                    if sysmon_available:
                        sysmon_status.configure(text="✓ Sysmon Enabled (Full monitoring)",
                                              text_color="#10b981")
                    else:
                        sysmon_status.configure(text="⚠ Sysmon Not Available (Limited monitoring)",
                                              text_color="#f59e0b")

                    # Apply current filters
                    apply_filters()

                    # Start monitoring
                    monitor.start_monitoring()

                    self.system_wide_monitor = monitor
                    monitor_state["monitor"] = monitor
                    monitor_state["monitoring"] = True
                    self.system_monitor_active = True

                    monitor_btn_text.set("⏸ Stop Monitoring")
                    monitor_btn.configure(fg_color="#059669")  # Green
                    status_label.configure(text="● Monitoring: Active", text_color="#10b981")

                    # Start auto-refresh
                    refresh_events()

                except Exception as e:
                    messagebox.showerror("Error", f"Failed to start monitoring:\n{str(e)}")
                    import traceback
                    traceback.print_exc()
            else:
                # Stop monitoring
                if monitor_state["monitor"]:
                    monitor_state["monitor"].stop_monitoring()
                    self.system_wide_monitor = None

                monitor_state["monitoring"] = False
                monitor_state["monitor"] = None
                self.system_monitor_active = False

                monitor_btn_text.set("▶ Start Monitoring")
                monitor_btn.configure(fg_color=self.colors["red"])
                status_label.configure(text="● Monitoring: Stopped", text_color="gray50")
                sysmon_status.configure(text="")

                # Cancel auto-refresh
                if monitor_state["update_job"]:
                    frame.after_cancel(monitor_state["update_job"])
                    monitor_state["update_job"] = None

        def apply_filters():
            """Apply current filter settings to the monitor"""
            if not monitor_state["monitor"]:
                return

            event_filter = monitor_state["monitor"].get_filter()

            # Apply PID filter (with optional child processes)
            pid_text = pid_filter_entry.get().strip()
            if pid_text:
                try:
                    pid = int(pid_text)

                    # Check if we should include child processes
                    if include_children_var.get():
                        # Get all child PIDs recursively
                        pids_to_filter = self.get_child_pids_recursive(pid)
                        pids_to_filter.add(pid)  # Include the parent PID too
                        event_filter.set_pid_set(pids_to_filter)
                    else:
                        # Just filter by the single PID
                        event_filter.set_pid(pid)
                except:
                    event_filter.set_pid(None)
            else:
                event_filter.set_pid(None)
                event_filter.set_pid_set(None)

            # Apply regex filter
            regex_text = regex_filter_entry.get().strip()
            if regex_text:
                event_filter.set_path_regex(regex_text)
            else:
                event_filter.set_path_regex(None)

            # Apply suspicious-only filter
            event_filter.set_suspicious_only(suspicious_var.get())

            monitor_state["current_filter"] = event_filter

            # Clear and refresh display with filtered events
            events_tree.delete(*events_tree.get_children())

            # Get ALL events from monitor and filter them for display
            monitor = monitor_state["monitor"]
            all_events = monitor.get_recent_events(count=5000)  # Get last 5000 events

            for event in all_events:
                # Apply current filter
                if not event_filter.matches(event):
                    continue

                # Check if suspicious for highlighting
                is_suspicious = event_filter.is_suspicious(event)
                tags = ('suspicious',) if is_suspicious else ()

                # Truncate long paths
                path = event.get('path', '')
                if len(str(path)) > 100:
                    path = str(path)[:97] + "..."

                # Insert event
                events_tree.insert("", "end", values=(
                    event.get('timestamp', ''),
                    event.get('pid', 0),
                    event.get('process_name', '')[:20],
                    event.get('event_type', ''),
                    event.get('operation', ''),
                    path,
                    event.get('result', '')
                ), tags=tags)

            # Update process info panel
            update_process_info()

        def clear_filters():
            """Clear all filters and show full event list"""
            if not monitor_state["monitor"]:
                return

            # Clear filter inputs
            pid_filter_entry.delete(0, tk.END)
            regex_filter_entry.delete(0, tk.END)
            suspicious_var.set(False)

            # Reset event type to "All"
            for ftype, btn in event_type_buttons.items():
                if ftype == "All":
                    btn.configure(fg_color=self.colors["red"])
                else:
                    btn.configure(fg_color="transparent")

            # Reset filter in monitor
            event_filter = monitor_state["monitor"].get_filter()
            event_filter.set_pid(None)
            event_filter.set_path_regex(None)
            event_filter.set_event_types(None)
            event_filter.set_suspicious_only(False)
            monitor_state["current_filter"] = event_filter

            # Clear and refresh display with ALL events
            events_tree.delete(*events_tree.get_children())

            monitor = monitor_state["monitor"]
            all_events = monitor.get_recent_events(count=5000)

            for event in all_events:
                # Check if suspicious for highlighting
                is_suspicious = event_filter.is_suspicious(event)
                tags = ('suspicious',) if is_suspicious else ()

                # Truncate long paths
                path = event.get('path', '')
                if len(str(path)) > 100:
                    path = str(path)[:97] + "..."

                # Insert event
                events_tree.insert("", "end", values=(
                    event.get('timestamp', ''),
                    event.get('pid', 0),
                    event.get('process_name', '')[:20],
                    event.get('event_type', ''),
                    event.get('operation', ''),
                    path,
                    event.get('result', '')
                ), tags=tags)

            # Hide process info panel
            process_info_panel.pack_forget()

        def update_process_info():
            """Update process info panel (Procmon-style) when PID filter is active"""
            pid_text = pid_filter_entry.get().strip()

            if pid_text and pid_text.isdigit():
                try:
                    pid = int(pid_text)
                    # Get process info using psutil
                    import psutil
                    proc = psutil.Process(pid)

                    # Build Procmon-style info string
                    info_lines = []
                    info_lines.append(f"Process:  {proc.name()}  (PID: {pid})")

                    try:
                        info_lines.append(f"Path:     {proc.exe()}")
                    except:
                        info_lines.append(f"Path:     [Access Denied]")

                    try:
                        cmdline = ' '.join(proc.cmdline())
                        if cmdline:
                            info_lines.append(f"Command:  {cmdline[:80]}{'...' if len(cmdline) > 80 else ''}")
                    except:
                        pass

                    try:
                        parent = proc.parent()
                        if parent:
                            info_lines.append(f"Parent:   {parent.name()} (PID: {parent.pid})")
                    except:
                        pass

                    process_info_label.configure(text="\n".join(info_lines))
                    process_info_panel.pack(fill="x", pady=(0, 10), before=events_frame)

                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                    process_info_label.configure(text=f"Process (PID: {pid}) - Not found or access denied")
                    process_info_panel.pack(fill="x", pady=(0, 10), before=events_frame)
            else:
                # No PID filter active, hide panel
                process_info_panel.pack_forget()

        def set_event_type_filter(event_type):
            """Set event type filter"""
            # Update button colors
            for ftype, btn in event_type_buttons.items():
                if ftype == event_type:
                    btn.configure(fg_color=self.colors["red"])
                else:
                    btn.configure(fg_color="transparent")

            # Apply filter
            if monitor_state["monitor"]:
                event_filter = monitor_state["monitor"].get_filter()
                if event_type == "All":
                    event_filter.set_event_types(None)
                else:
                    event_filter.set_event_types([event_type])

                monitor_state["current_filter"] = event_filter

                # Clear and refresh display with filtered events
                events_tree.delete(*events_tree.get_children())

                # Get ALL events from monitor and filter them for display
                monitor = monitor_state["monitor"]
                all_events = monitor.get_recent_events(count=5000)

                for event in all_events:
                    # Apply current filter
                    if not event_filter.matches(event):
                        continue

                    # Check if suspicious for highlighting
                    is_suspicious = event_filter.is_suspicious(event)
                    tags = ('suspicious',) if is_suspicious else ()

                    # Truncate long paths
                    path = event.get('path', '')
                    if len(str(path)) > 100:
                        path = str(path)[:97] + "..."

                    # Insert event
                    events_tree.insert("", "end", values=(
                        event.get('timestamp', ''),
                        event.get('pid', 0),
                        event.get('process_name', '')[:20],
                        event.get('event_type', ''),
                        event.get('operation', ''),
                        path,
                        event.get('result', '')
                    ), tags=tags)

                # Update process info panel
                update_process_info()

        def refresh_events():
            """Refresh the events display (incremental updates)"""
            if not monitor_state["monitoring"] or not monitor_state["monitor"]:
                return

            try:
                monitor = monitor_state["monitor"]

                # Get events since last update (incremental)
                new_events = monitor.get_events_since(monitor_state["last_update_time"])

                # Add only new events to tree (incremental update for performance)
                for event in new_events:
                    # Apply current filter to new events
                    if monitor_state["current_filter"] and not monitor_state["current_filter"].matches(event):
                        continue

                    # Check if suspicious for highlighting
                    is_suspicious = False
                    if monitor_state["current_filter"]:
                        is_suspicious = monitor_state["current_filter"].is_suspicious(event)
                    tags = ('suspicious',) if is_suspicious else ()

                    # Truncate long paths
                    path = event.get('path', '')
                    if len(str(path)) > 100:
                        path = str(path)[:97] + "..."

                    # Insert event
                    events_tree.insert("", "end", values=(
                        event.get('timestamp', ''),
                        event.get('pid', 0),
                        event.get('process_name', '')[:20],  # Truncate process name
                        event.get('event_type', ''),
                        event.get('operation', ''),
                        path,
                        event.get('result', '')
                    ), tags=tags)

                    monitor_state["event_count"] += 1

                # Limit tree size for performance (keep last 5000 events)
                children = events_tree.get_children()
                if len(children) > 5000:
                    for item in children[:len(children) - 5000]:
                        events_tree.delete(item)

                # Update statistics
                stats = monitor.get_stats()
                stats_label.configure(
                    text=f"Total: {stats['total_events']} | "
                         f"File: {stats['file_events']} | "
                         f"Registry: {stats['registry_events']} | "
                         f"Network: {stats['network_events']} | "
                         f"Process: {stats['process_events']} | "
                         f"DNS: {stats.get('dns_events', 0)}"
                )

                # Update last update time
                monitor_state["last_update_time"] = datetime.now()

                # Schedule next refresh (500ms)
                monitor_state["update_job"] = frame.after(500, refresh_events)

            except Exception as e:
                print(f"Error refreshing events: {e}")
                import traceback
                traceback.print_exc()

        def export_events_to_csv():
            """Export events to CSV"""
            if not monitor_state["monitor"]:
                messagebox.showwarning("No Data", "No events to export. Start monitoring first.")
                return

            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"mad_system_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )

            if filepath:
                try:
                    import csv
                    monitor = monitor_state["monitor"]
                    events = monitor.get_recent_events(count=len(monitor.events))

                    with open(filepath, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Timestamp', 'PID', 'Process', 'Event Type',
                                       'Operation', 'Path', 'Result', 'Detail'])

                        for event in events:
                            writer.writerow([
                                event.get('time_full', ''),
                                event.get('pid', ''),
                                event.get('process_name', ''),
                                event.get('event_type', ''),
                                event.get('operation', ''),
                                event.get('path', ''),
                                event.get('result', ''),
                                event.get('detail', '')
                            ])

                    messagebox.showinfo("Success", f"Exported {len(events)} events to:\n{filepath}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to export: {str(e)}")

        def clear_events_display():
            """Clear events display and stats"""
            if monitor_state["monitor"]:
                monitor_state["monitor"].clear_events()
                events_tree.delete(*events_tree.get_children())
                monitor_state["event_count"] = 0
                stats_label.configure(text="Total: 0 | File: 0 | Registry: 0 | Network: 0 | Process: 0 | DNS: 0")

        def focus_on_pid():
            """Focus monitoring on selected PID"""
            selection = events_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select an event first")
                return

            item = events_tree.item(selection[0])
            pid = item['values'][1]  # PID column

            pid_filter_entry.delete(0, tk.END)
            pid_filter_entry.insert(0, str(pid))
            apply_filters()
            refresh_events()

        def copy_path_to_clipboard():
            """Copy event path to clipboard"""
            selection = events_tree.selection()
            if not selection:
                return

            item = events_tree.item(selection[0])
            path = item['values'][5]  # Path column

            self.root.clipboard_clear()
            self.root.clipboard_append(path)
            messagebox.showinfo("Copied", f"Path copied to clipboard:\n{path}")

        def remove_event():
            """Remove selected event from display"""
            selection = events_tree.selection()
            if selection:
                events_tree.delete(selection[0])

        # Connect button commands
        monitor_btn.configure(command=toggle_monitoring)
        export_btn.configure(command=export_events_to_csv)
        clear_btn.configure(command=clear_events_display)
        apply_filter_btn.configure(command=apply_filters)
        clear_filter_btn.configure(command=clear_filters)
        suspicious_check.configure(command=lambda: apply_filters() if monitor_state["monitoring"] else None)

        # Connect event type filter buttons
        for ftype, btn in event_type_buttons.items():
            btn.configure(command=lambda f=ftype: set_event_type_filter(f))

        # Connect context menu commands
        events_context_menu.entryconfig(0, command=focus_on_pid)
        events_context_menu.entryconfig(1, command=copy_path_to_clipboard)
        events_context_menu.entryconfig(5, command=remove_event)  # Updated index after adding IOC extraction menu items

        # Store toggle function for auto-start
        self.live_events_toggle_monitoring = toggle_monitoring

        self.analysis_subtabs["live_events"] = frame

    # ==================== TAB NAVIGATION ====================
    def show_tab(self, tab_name):
        """Switch between main tabs"""
        # Hide all tabs
        for tab in self.tabs.values():
            tab.pack_forget()

        # Reset all button colors
        self.btn_new_case.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["navy"]
        )
        self.btn_current_case.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["navy"]
        )
        self.btn_analysis.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["navy"]
        )
        self.btn_yara_rules.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["navy"]
        )
        self.btn_settings.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["navy"]
        )

        # Show selected tab
        self.tabs[tab_name].pack(fill="both", expand=True)

        # Highlight active button
        if tab_name == "new_case":
            self.btn_new_case.configure(
                fg_color=self.colors["navy"],
                border_width=0
            )
        elif tab_name == "current_case":
            self.btn_current_case.configure(
                fg_color=self.colors["navy"],
                border_width=0
            )
            self.update_current_case_display()
        elif tab_name == "analysis":
            self.btn_analysis.configure(
                fg_color=self.colors["navy"],
                border_width=0
            )
        elif tab_name == "yara_rules":
            self.btn_yara_rules.configure(
                fg_color=self.colors["navy"],
                border_width=0
            )
            self.refresh_yara_rules_list()
        elif tab_name == "settings":
            self.btn_settings.configure(
                fg_color=self.colors["navy"],
                border_width=0
            )

    def show_analysis_subtab(self, subtab_name):
        """Switch between analysis sub-tabs"""
        # Hide all subtabs
        for subtab in self.analysis_subtabs.values():
            subtab.pack_forget()
        
        # Reset button colors
        self.btn_processes.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        self.btn_network.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        self.btn_live_events.configure(
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )

        # Show selected subtab
        self.analysis_subtabs[subtab_name].pack(fill="both", expand=True)

        # Highlight button
        if subtab_name == "processes":
            self.btn_processes.configure(
                fg_color=self.colors["red"],
                border_width=0
            )
        elif subtab_name == "network":
            self.btn_network.configure(
                fg_color=self.colors["red"],
                border_width=0
            )
        elif subtab_name == "live_events":
            self.btn_live_events.configure(
                fg_color=self.colors["red"],
                border_width=0
            )
            # Auto-start monitoring if not already active
            if self.live_events_toggle_monitoring and not self.system_monitor_active:
                print("[GUI] Auto-starting Live Events monitoring...")
                self.live_events_toggle_monitoring()
    
    # ==================== EVENT HANDLERS ====================
    def on_upload_method_change(self):
        """Handle upload method radio button change"""
        method = self.upload_method.get()
        if method == "url":
            self.url_input_frame.pack(pady=(10, 0), before=self.btn_new_case_upload)
            self.btn_new_case_upload.configure(text="Download and Start Case")
        else:
            self.url_input_frame.pack_forget()
            self.btn_new_case_upload.configure(text="Upload File to Start Case")

    def handle_new_case_upload(self):
        """Handle file upload or URL download for new case"""
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return

        # Validate analyst name and report URL
        analyst_name = self.analyst_name_entry.get().strip()
        report_url = self.report_url_entry.get().strip()

        if not analyst_name:
            messagebox.showwarning("Missing Information", "Please enter an Analyst Name")
            self.analyst_name_entry.focus()
            return

        if not report_url:
            messagebox.showwarning("Missing Information", "Please enter a Report URL")
            self.report_url_entry.focus()
            return

        # Check upload method
        method = self.upload_method.get()

        if method == "url":
            # Get URLs from text box
            url_text = self.url_input_textbox.get("1.0", "end-1c").strip()
            if not url_text:
                messagebox.showwarning("Missing URLs", "Please enter at least one URL")
                self.url_input_textbox.focus()
                return

            # Parse URLs (one per line)
            urls = [url.strip() for url in url_text.split('\n') if url.strip()]
            if not urls:
                messagebox.showwarning("Missing URLs", "Please enter at least one valid URL")
                return

            self.process_new_case_urls(urls, analyst_name, report_url)
        else:
            # File upload mode
            files = filedialog.askopenfilenames(title="Select files to analyze")
            if not files:
                return

            self.process_new_case_files(list(files), analyst_name, report_url)
    
    def process_new_case_files(self, files, analyst_name, report_url):
        """Process files for new case with progress bar"""
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return
        
        self.scan_in_progress = True
        self.cancel_scan = False
        
        # Create progress window
        self.create_progress_window(len(files))
        
        # Run scanning in separate thread to keep UI responsive
        scan_thread = threading.Thread(
            target=self._scan_files_thread,
            args=(files, analyst_name, report_url),
            daemon=True
        )
        scan_thread.start()
    
    def _scan_files_thread(self, files, analyst_name, report_url):
        """Background thread for file scanning"""
        try:
            # Create case structure
            case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
            files_dir = os.path.join(case_dir, "files")
            os.makedirs(files_dir, exist_ok=True)

            # Create network case folder if enabled (use analyst name from form)
            network_case_path = ""
            if report_url and self.settings_manager.get("network.enable_network_case_folder", False):
                network_path = self.settings_manager.get_network_case_folder_path(report_url, analyst_name)
                if network_path:
                    try:
                        os.makedirs(network_path, exist_ok=True)
                        os.makedirs(os.path.join(network_path, "files"), exist_ok=True)
                        network_case_path = network_path
                        print(f"Created network case folder: {network_path}")
                    except Exception as e:
                        print(f"Warning: Could not create network folder: {e}")

            # Initialize case data
            case_data = {
                "id": case_id,
                "created": datetime.now().isoformat(),
                "status": "ACTIVE",
                "analyst_name": analyst_name,
                "report_url": report_url,
                "network_case_path": network_case_path,
                "files": [],
                "total_threats": 0,
                "total_vt_hits": 0
            }
            
            # Process each file with progress updates
            for i, file_path in enumerate(files):
                if self.cancel_scan:
                    self.root.after(0, self.close_progress_window)
                    self.root.after(0, lambda: messagebox.showinfo("Cancelled", "Scan cancelled by user"))
                    self.scan_in_progress = False
                    return
                
                filename = os.path.basename(file_path)
                
                # Update progress
                self.root.after(0, self.update_progress, i + 1, len(files), f"Scanning: {filename}")
                
                # Process file
                file_info = self.case_manager.process_file(file_path, files_dir, case_id)
                case_data["files"].append(file_info)
                
                # Update case statistics
                has_yara = len(file_info["yara_matches"]) > 0
                has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                has_vt = file_info["vt_hits"] > 0
                
                if has_yara or has_thq or has_vt:
                    case_data["total_threats"] += 1
                case_data["total_vt_hits"] += file_info["vt_hits"]
            
            # Save case metadata
            self.case_manager.save_case_metadata(case_dir, case_data)
            self.current_case = case_data
            self.case_manager.current_case = case_data  # Also update case_manager's reference
            
            # Close progress and show success
            self.root.after(0, self.close_progress_window)
            self.root.after(0, lambda: self.new_case_status.configure(
                text=f"✓ Case created: {case_data['id']} | Files: {len(files)} | Threats: {case_data['total_threats']}"
            ))
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"New case created: {case_data['id']}\n"
                f"Analyst: {analyst_name}\n"
                f"Files processed: {len(files)}\n"
                f"Threats detected: {case_data['total_threats']}"
            ))
            
            # Clear form and switch tabs
            self.root.after(0, lambda: self.analyst_name_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.report_url_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.show_tab("current_case"))
            
        except Exception as e:
            self.root.after(0, self.close_progress_window)
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to create case: {str(e)}"))
            self.root.after(0, lambda: self.new_case_status.configure(text="✗ Error creating case"))
        
        finally:
            self.scan_in_progress = False

    def process_new_case_urls(self, urls, analyst_name, report_url):
        """Process URLs for new case with progress bar"""
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return

        self.scan_in_progress = True
        self.cancel_scan = False

        # Create progress window
        self.create_progress_window(len(urls))

        # Run downloading and scanning in separate thread
        scan_thread = threading.Thread(
            target=self._scan_urls_thread,
            args=(urls, analyst_name, report_url),
            daemon=True
        )
        scan_thread.start()

    def _scan_urls_thread(self, urls, analyst_name, report_url):
        """Background thread for URL downloading and file scanning"""
        try:
            # Create case structure
            case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
            files_dir = os.path.join(case_dir, "files")
            os.makedirs(files_dir, exist_ok=True)

            # Create network case folder if enabled (use analyst name from form)
            network_case_path = ""
            if report_url and self.settings_manager.get("network.enable_network_case_folder", False):
                network_path = self.settings_manager.get_network_case_folder_path(report_url, analyst_name)
                if network_path:
                    try:
                        os.makedirs(network_path, exist_ok=True)
                        os.makedirs(os.path.join(network_path, "files"), exist_ok=True)
                        network_case_path = network_path
                        print(f"Created network case folder: {network_path}")
                    except Exception as e:
                        print(f"Warning: Could not create network folder: {e}")

            # Initialize case data
            case_data = {
                "id": case_id,
                "created": datetime.now().isoformat(),
                "status": "ACTIVE",
                "analyst_name": analyst_name,
                "report_url": report_url,
                "network_case_path": network_case_path,
                "files": [],
                "total_threats": 0,
                "total_vt_hits": 0,
                "iocs": {
                    "urls": [],
                    "ips": [],
                    "domains": []
                }
            }

            # Set current case so downloads are tracked
            self.case_manager.current_case = case_data

            downloaded_files = []
            failed_downloads = []

            # Download and process each URL
            for i, url in enumerate(urls):
                if self.cancel_scan:
                    self.root.after(0, self.close_progress_window)
                    self.root.after(0, lambda: messagebox.showinfo("Cancelled", "Scan cancelled by user"))
                    self.scan_in_progress = False
                    return

                # Update progress - downloading
                self.root.after(0, self.update_progress, i + 1, len(urls), f"Downloading: {url[:50]}...")

                # Download file
                success, file_path, error = self.case_manager.download_file_from_url(url)

                if success:
                    downloaded_files.append(file_path)

                    # Update progress - scanning
                    filename = os.path.basename(file_path)
                    self.root.after(0, self.update_progress, i + 1, len(urls), f"Scanning: {filename}")

                    # Process file
                    file_info = self.case_manager.process_file(file_path, files_dir, case_id)
                    file_info["source_url"] = url  # Track source URL
                    case_data["files"].append(file_info)

                    # Update case statistics
                    has_yara = len(file_info["yara_matches"]) > 0
                    has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                    has_vt = file_info["vt_hits"] > 0

                    if has_yara or has_thq or has_vt:
                        case_data["total_threats"] += 1
                    case_data["total_vt_hits"] += file_info["vt_hits"]

                    # Clean up temporary file
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except:
                        pass
                else:
                    failed_downloads.append(f"{url}: {error}")

            # Save case metadata
            self.case_manager.save_case_metadata(case_dir, case_data)
            self.current_case = case_data
            self.case_manager.current_case = case_data

            # Close progress and show success
            self.root.after(0, self.close_progress_window)

            success_msg = f"New case created: {case_data['id']}\n"
            success_msg += f"Analyst: {analyst_name}\n"
            success_msg += f"URLs processed: {len(urls)}\n"
            success_msg += f"Files downloaded: {len(downloaded_files)}\n"
            success_msg += f"Threats detected: {case_data['total_threats']}"

            if failed_downloads:
                success_msg += f"\n\nFailed downloads ({len(failed_downloads)}):\n"
                success_msg += "\n".join(failed_downloads[:5])
                if len(failed_downloads) > 5:
                    success_msg += f"\n... and {len(failed_downloads) - 5} more"

            self.root.after(0, lambda: self.new_case_status.configure(
                text=f"✓ Case created: {case_data['id']} | Files: {len(downloaded_files)} | Threats: {case_data['total_threats']}"
            ))
            self.root.after(0, lambda: messagebox.showinfo("Success", success_msg))

            # Clear form and switch tabs
            self.root.after(0, lambda: self.analyst_name_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.report_url_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.url_input_textbox.delete("1.0", "end"))
            self.root.after(0, lambda: self.show_tab("current_case"))

        except Exception as e:
            self.root.after(0, self.close_progress_window)
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to create case: {str(e)}"))
            self.root.after(0, lambda: self.new_case_status.configure(text="✗ Error creating case"))
            import traceback
            traceback.print_exc()

        finally:
            self.scan_in_progress = False

    def create_progress_window(self, total_files):
        """Create progress window"""
        self.progress_window = ctk.CTkToplevel(self.root)
        self.progress_window.title("Scanning Files")
        self.progress_window.geometry("550x250")
        self.progress_window.transient(self.root)
        self.progress_window.grab_set()
        self.progress_window.resizable(False, False)
        
        # Center the window
        self.progress_window.update_idletasks()
        x = (self.progress_window.winfo_screenwidth() // 2) - (550 // 2)
        y = (self.progress_window.winfo_screenheight() // 2) - (250 // 2)
        self.progress_window.geometry(f"550x250+{x}+{y}")
        
        # Main container
        container = ctk.CTkFrame(self.progress_window, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Title
        title = ctk.CTkLabel(
            container,
            text="Scanning Files",
            font=Fonts.title_large
        )
        title.pack(pady=(0, 5))
        
        subtitle = ctk.CTkLabel(
            container,
            text="YARA & Threat Intelligence Analysis",
            font=Fonts.body,
            text_color="gray60"
        )
        subtitle.pack(pady=(0, 20))
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(container, width=450, height=20)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)
        
        # Status label
        self.progress_label = ctk.CTkLabel(
            container,
            text=f"Processing 0 of {total_files} files...",
            font=Fonts.body_large_bold
        )
        self.progress_label.pack(pady=10)
        
        # Current file label
        self.current_file_label = ctk.CTkLabel(
            container,
            text="Initializing...",
            font=Fonts.helper,
            text_color="gray60"
        )
        self.current_file_label.pack(pady=5)
        
        # Cancel button
        cancel_btn = ctk.CTkButton(
            container,
            text="Cancel Scan",
            command=self.cancel_scan_operation,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            width=120,
            height=35
        )
        cancel_btn.pack(pady=15)
    
    def update_progress(self, current, total, current_file):
        """Update progress bar and labels"""
        if self.progress_window and self.progress_window.winfo_exists():
            progress = current / total
            self.progress_bar.set(progress)
            self.progress_label.configure(text=f"Processing {current} of {total} files...")
            self.current_file_label.configure(text=current_file)
    
    def cancel_scan_operation(self):
        """Cancel the current scan"""
        self.cancel_scan = True
        if self.progress_window and self.progress_window.winfo_exists():
            self.progress_window.destroy()
    
    def close_progress_window(self):
        """Close progress window"""
        if self.progress_window and self.progress_window.winfo_exists():
            self.progress_window.destroy()
            self.progress_window = None
    
    def handle_add_files(self):
        """Handle adding files to existing case with progress window"""
        if not self.current_case:
            messagebox.showwarning("No Case", "Please create a case first")
            return

        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return

        files = filedialog.askopenfilenames(title="Add files to case")
        if not files:
            return

        self.scan_in_progress = True
        self.cancel_scan = False

        # Create progress window
        self.create_progress_window(len(files))

        # Run in thread
        def add_files_thread():
            try:
                case_id = self.current_case["id"]
                case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
                files_dir = os.path.join(case_dir, "files")

                for i, file_path in enumerate(files):
                    if self.cancel_scan:
                        self.root.after(0, self.close_progress_window)
                        self.root.after(0, lambda: messagebox.showinfo("Cancelled", "Scan cancelled by user"))
                        self.scan_in_progress = False
                        return

                    filename = os.path.basename(file_path)

                    # Update progress
                    self.root.after(0, self.update_progress, i + 1, len(files), f"Scanning: {filename}")

                    # Process file
                    file_info = self.case_manager.process_file(file_path, files_dir, case_id)
                    self.current_case["files"].append(file_info)

                    # Update case statistics
                    if not file_info.get("whitelisted", False):
                        has_yara = len(file_info["yara_matches"]) > 0
                        has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                        has_vt = file_info["vt_hits"] > 0

                        if has_yara or has_thq or has_vt:
                            self.current_case["total_threats"] += 1
                        self.current_case["total_vt_hits"] += file_info["vt_hits"]

                # Save case metadata
                self.case_manager.save_case_metadata(case_dir, self.current_case)

                # Close progress window and update display
                self.root.after(0, self.close_progress_window)
                self.root.after(0, self.update_current_case_display)
                self.root.after(0, lambda: messagebox.showinfo(
                    "Success",
                    f"Added {len(files)} files to case\n"
                    f"Total files: {len(self.current_case['files'])}\n"
                    f"Total threats: {self.current_case['total_threats']}"
                ))

            except Exception as e:
                self.root.after(0, self.close_progress_window)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to add files: {str(e)}"))
                import traceback
                traceback.print_exc()

            finally:
                self.scan_in_progress = False

        import threading
        thread = threading.Thread(target=add_files_thread, daemon=True)
        thread.start()
    
    def handle_add_ioc(self):
        """Show dialog to add IOC to current case"""
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case to add IOC to")
            return

        # Create dialog window
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Add IOC")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (300 // 2)
        dialog.geometry(f"500x300+{x}+{y}")

        # Content frame
        content = ctk.CTkFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(content, text="Add Indicator of Compromise",
                                   font=Fonts.title_medium)
        title_label.pack(pady=(0, 15))

        # IOC Type selection
        type_label = ctk.CTkLabel(content, text="IOC Type:",
                                  font=Fonts.body_bold,
                                  anchor="w")
        type_label.pack(anchor="w", pady=(0, 5))

        ioc_type_var = tk.StringVar(value="urls")
        type_frame = ctk.CTkFrame(content, fg_color="transparent")
        type_frame.pack(anchor="w", pady=(0, 10))

        ctk.CTkRadioButton(type_frame, text="URL", variable=ioc_type_var, value="urls",
                          fg_color=self.colors["red"]).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(type_frame, text="IP Address", variable=ioc_type_var, value="ips",
                          fg_color=self.colors["red"]).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(type_frame, text="Domain", variable=ioc_type_var, value="domains",
                          fg_color=self.colors["red"]).pack(side="left")

        # IOC Value input
        value_label = ctk.CTkLabel(content, text="IOC Value:",
                                   font=Fonts.body_bold,
                                   anchor="w")
        value_label.pack(anchor="w", pady=(0, 5))

        ioc_value_entry = ctk.CTkEntry(content, width=450, height=35)
        ioc_value_entry.pack(pady=(0, 20))
        ioc_value_entry.focus()

        # Buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=(10, 0))

        def add_ioc():
            ioc_type = ioc_type_var.get()
            ioc_value = ioc_value_entry.get().strip()

            if not ioc_value:
                messagebox.showwarning("Empty Value", "Please enter an IOC value")
                return

            # Add IOC to case
            self.case_manager.add_ioc(ioc_type, ioc_value)

            # Refresh IOC display
            self.refresh_iocs_display()

            messagebox.showinfo("Success", f"IOC added successfully!\n\nType: {ioc_type}\nValue: {ioc_value}")
            dialog.destroy()

        btn_add = ctk.CTkButton(btn_frame, text="Add IOC", command=add_ioc,
                               width=120, height=35,
                               fg_color=self.colors["red"],
                               hover_color=self.colors["red_dark"])
        btn_add.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy,
                                   width=120, height=35,
                                   fg_color="gray40",
                                   hover_color="gray30")
        btn_cancel.pack(side="left", padx=5)

    def refresh_iocs_display(self):
        """Refresh the IOCs display in the Current Case tab"""
        if not self.current_case:
            return

        iocs = self.current_case.get("iocs", {"urls": [], "ips": [], "domains": []})

        # Clear existing content
        self.iocs_urls_list.delete("1.0", "end")
        self.iocs_ips_list.delete("1.0", "end")
        self.iocs_domains_list.delete("1.0", "end")

        # Display IOCs
        if iocs.get("urls"):
            self.iocs_urls_list.insert("1.0", "\n".join(iocs["urls"]))
        else:
            self.iocs_urls_list.insert("1.0", "No URLs recorded")

        if iocs.get("ips"):
            self.iocs_ips_list.insert("1.0", "\n".join(iocs["ips"]))
        else:
            self.iocs_ips_list.insert("1.0", "No IP addresses recorded")

        if iocs.get("domains"):
            self.iocs_domains_list.insert("1.0", "\n".join(iocs["domains"]))
        else:
            self.iocs_domains_list.insert("1.0", "No domains recorded")

    def handle_save_notes(self):
        """Save notes to the current case"""
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case to save notes to")
            return

        notes = self.notes_textbox.get("1.0", "end-1c").strip()

        if not notes:
            messagebox.showwarning("Empty Notes", "Please enter some notes before saving")
            return

        try:
            # Add notes to case data
            self.current_case["notes"] = notes

            # Get case directory
            case_dir = os.path.join(self.case_manager.case_storage_path, self.current_case["id"])

            # Save updated case metadata
            self.case_manager.save_case_metadata(case_dir, self.current_case)

            # Also save notes as a separate text file
            self.case_manager.save_case_notes(case_dir, notes)

            # Get the notes file path for display
            notes_file = os.path.join(case_dir, "case_notes.txt")

            messagebox.showinfo(
                "Success",
                f"Notes saved successfully!\n\n"
                f"Location:\n{notes_file}\n\n"
                f"Characters: {len(notes)}"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save notes: {str(e)}")
    
    # ==================== DISPLAY UPDATES ====================
    def update_current_case_display(self):
        """Update the current case tab display"""
        if not self.current_case:
            self.case_status_label.configure(text="")
            return
        
        # Update status badge
        self.case_status_label.configure(text="ACTIVE", fg_color="#2D7A3E")
        
        # Clear and rebuild case details
        for widget in self.case_info_frame.winfo_children():
            widget.destroy()
        
        # Use Analyst Name and Report URL instead of Case ID and Created
        details = [
            ("Analyst Name:", self.current_case.get("analyst_name", "N/A")),
            ("Report URL:", self.current_case.get("report_url", "N/A")),
            ("Files:", str(len(self.current_case["files"]))),
            ("Threats:", str(self.current_case["total_threats"]))
        ]
        
        for i, (label, value) in enumerate(details):
            row = i // 2
            col = i % 2
            
            detail_frame = ctk.CTkFrame(self.case_info_frame, fg_color="transparent")
            detail_frame.grid(row=row, column=col, padx=10, pady=5, sticky="w")
            
            lbl = ctk.CTkLabel(detail_frame, text=label, 
                              text_color="gray60", font=Fonts.helper)
            lbl.pack(anchor="w")
            
            val = ctk.CTkLabel(detail_frame, text=value,
                              font=Fonts.body_bold,
                              text_color="white")
            val.pack(anchor="w")
        
        # Clear and rebuild files list
        for widget in self.files_list_frame.winfo_children():
            widget.destroy()
        
        for file_info in self.current_case["files"]:
            self.create_file_card(file_info)
        
        # Load existing notes if available
        if "notes" in self.current_case:
            self.notes_textbox.delete("1.0", "end")
            self.notes_textbox.insert("1.0", self.current_case["notes"])

        # Refresh IOCs display
        self.refresh_iocs_display()

    def create_file_card(self, file_info):
        """Create an expandable card for displaying file information"""
        yara_matches = file_info.get("yara_matches", [])
        thq_family = file_info.get("thq_family", "Unknown")
        is_whitelisted = file_info.get("whitelisted", False)
        has_threats = len(yara_matches) > 0 or file_info.get("vt_hits", 0) > 0
        
        # Determine card color
        if is_whitelisted:
            card_color = "#1a4d2e"  # Dark green for whitelisted
        elif has_threats:
            card_color = "#5c1c1c"  # Dark red for threats
        else:
            card_color = "#2a2a2a"  # Dark gray for clean
        
        # Main card frame - make it clickable
        card_frame = ctk.CTkFrame(
            self.files_list_frame, 
            corner_radius=8,
            fg_color=card_color,
            cursor="hand2"
        )
        card_frame.pack(fill="x", padx=10, pady=5)
        
        # Header (always visible)
        header_frame = ctk.CTkFrame(card_frame, fg_color="transparent", cursor="hand2")
        header_frame.pack(fill="x", padx=15, pady=12)
        header_frame.grid_columnconfigure(0, weight=1)
        
        # Left side - file info
        left_frame = ctk.CTkFrame(header_frame, fg_color="transparent", cursor="hand2")
        left_frame.grid(row=0, column=0, sticky="w")
        
        name_label = ctk.CTkLabel(
            left_frame, text=file_info["filename"],
            font=Fonts.title_medium,
            text_color="white",
            cursor="hand2"
        )
        name_label.pack(anchor="w")
        
        # YARA and THQ matches display in one line
        if is_whitelisted:
            # Show BENIGN for whitelisted files
            info_line = "✅ BENIGN (Whitelisted)"
            label_color = "#2ecc71"  # Green for benign
        else:
            yara_display = self.case_manager.get_yara_display_text(yara_matches)
            thq_display = thq_family if thq_family and thq_family != "Unknown" else "N/A"

            info_line = f"YARA: {yara_display}  |  THQ: {thq_display}"

            # Determine color: Red for YARA, Orange for THQ-only, Gray for neither
            has_yara = bool(yara_matches)
            has_thq = thq_family and thq_family not in ["Unknown", "N/A"]
            if has_yara:
                label_color = self.colors["red"]  # Red for YARA matches
            elif has_thq:
                label_color = "#FF8C00"  # Orange for THQ-only
            else:
                label_color = "gray60"

        yara_thq_label = ctk.CTkLabel(
            left_frame,
            text=info_line,
            text_color=label_color,
            font=Fonts.body_bold,
            cursor="hand2"
        )
        yara_thq_label.pack(anchor="w", pady=(3, 0))
        
        # File size and timestamp
        size_kb = file_info.get("file_size", 0) / 1024
        info_text = f"{size_kb:.2f} KB | {datetime.fromisoformat(file_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}"
        info_label = ctk.CTkLabel(
            left_frame, text=info_text,
            text_color="gray60", font=Fonts.helper,
            cursor="hand2"
        )
        info_label.pack(anchor="w", pady=(2, 0))

        # Right side - expand indicator only
        right_frame = ctk.CTkFrame(header_frame, fg_color="transparent", cursor="hand2")
        right_frame.grid(row=0, column=1, sticky="e", padx=(10, 0))

        # Expand/Collapse indicator
        details_visible = [False]
        details_frame = ctk.CTkFrame(card_frame, fg_color="#0d1520", height=200)

        expand_indicator = ctk.CTkLabel(
            right_frame,
            text="▼",
            font=Fonts.body_large,
            text_color="gray60",
            cursor="hand2"
        )
        expand_indicator.pack(side="top")

        # Buttons row (horizontal layout below header)
        buttons_row = ctk.CTkFrame(card_frame, fg_color="transparent")
        buttons_row.pack(fill="x", padx=15, pady=(0, 12))

        # Copy details button
        def copy_details(event):
            copy_text = f"""File Name: {file_info['filename']}
MD5: {file_info['md5']}
SHA256: {file_info['sha256']}
File Size: {file_info['file_size']} bytes"""

            self.root.clipboard_clear()
            self.root.clipboard_append(copy_text)
            self.root.update()

            original_text = copy_btn.cget("text")
            copy_btn.configure(text="✓ Copied!")
            self.root.after(1500, lambda: copy_btn.configure(text=original_text))
            return "break"

        copy_btn = ctk.CTkButton(
            buttons_row,
            text="📋 Copy",
            width=100,
            height=28,
            font=Fonts.helper,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            cursor="hand2"
        )
        copy_btn.pack(side="left", padx=(0, 5))
        copy_btn.bind("<Button-1>", copy_details)

        # View Strings button
        def view_strings_click(event):
            # Get file path from file_info (stored as 'storage_path')
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                self.view_file_strings(file_path, file_info['filename'])
            else:
                messagebox.showerror("File Not Found", f"File not found: {file_path}")
            return "break"

        view_strings_btn = ctk.CTkButton(
            buttons_row,
            text="📄 Strings",
            width=100,
            height=28,
            font=Fonts.helper,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"],
            hover_color=self.colors["navy"],
            cursor="hand2"
        )
        view_strings_btn.pack(side="left", padx=5)
        view_strings_btn.bind("<Button-1>", view_strings_click)

        # View File button
        def view_file_click(event):
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                # Determine if file is likely text or binary
                viewer = get_viewer_executor()
                info = viewer.get_file_info(file_path)

                if info.get('is_text', False):
                    self.view_file_text(file_path, file_info['filename'])
                else:
                    self.view_file_hex(file_path, file_info['filename'])
            else:
                messagebox.showerror("File Not Found", f"File not found: {file_path}")
            return "break"

        view_file_btn = ctk.CTkButton(
            buttons_row,
            text="👁 View",
            width=90,
            height=28,
            font=Fonts.helper,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"],
            hover_color=self.colors["navy"],
            cursor="hand2"
        )
        view_file_btn.pack(side="left", padx=5)
        view_file_btn.bind("<Button-1>", view_file_click)

        # Execute File button
        def execute_file_click(event):
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                self.execute_file(file_path, file_info['filename'])
            else:
                messagebox.showerror("File Not Found", f"File not found: {file_path}")
            return "break"

        execute_file_btn = ctk.CTkButton(
            buttons_row,
            text="▶️ Execute",
            width=110,
            height=28,
            font=Fonts.helper,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            cursor="hand2"
        )
        execute_file_btn.pack(side="left", padx=5)
        execute_file_btn.bind("<Button-1>", execute_file_click)

        # Execute (Suspended) button
        def execute_suspended_click(event):
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                # Check if file is EXE or MSI (only these support suspended execution)
                if file_path.lower().endswith(('.exe', '.msi')):
                    self.execute_file(file_path, file_info['filename'], suspended=True)
                else:
                    messagebox.showinfo(
                        "Not Supported",
                        "Suspended execution is only supported for EXE and MSI files."
                    )
            else:
                messagebox.showerror("File Not Found", f"File not found: {file_path}")
            return "break"

        execute_suspended_btn = ctk.CTkButton(
            buttons_row,
            text="⏸ Suspended",
            width=120,
            height=28,
            font=Fonts.helper,
            fg_color="transparent",
            border_width=2,
            border_color="#FFA500",
            text_color="#FFA500",
            hover_color=self.colors["navy"],
            cursor="hand2"
        )
        execute_suspended_btn.pack(side="left", padx=5)
        execute_suspended_btn.bind("<Button-1>", execute_suspended_click)

        # Delete File button
        def delete_file_click(event):
            file_path = file_info.get('storage_path', '')
            file_name = file_info['filename']

            # Confirmation dialog
            result = messagebox.askyesno(
                "Delete File",
                f"Are you sure you want to delete this file from the case?\n\n{file_name}\n\nThis will remove it from disk and the case.",
                icon='warning'
            )

            if result:
                self.delete_file_from_case(file_info, card_frame)
            return "break"

        delete_btn = ctk.CTkButton(
            buttons_row,
            text="🗑 Delete",
            width=100,
            height=28,
            font=Fonts.helper,
            fg_color="#8B0000",  # Dark red for danger
            hover_color="#5c0000",
            cursor="hand2"
        )
        delete_btn.pack(side="left", padx=5)
        delete_btn.bind("<Button-1>", delete_file_click)

        def toggle_details(event=None):
            if details_visible[0]:
                details_frame.pack_forget()
                expand_indicator.configure(text="▼")
                details_visible[0] = False
            else:
                if len(details_frame.winfo_children()) == 0:
                    self.populate_file_details(details_frame, file_info)
                details_frame.pack(fill="both", expand=True, padx=15, pady=(0, 12))
                expand_indicator.configure(text="▲")
                details_visible[0] = True
            card_frame.update_idletasks()
            self.root.update_idletasks()
        
        # Bind click events to all elements
        card_frame.bind("<Button-1>", toggle_details)
        header_frame.bind("<Button-1>", toggle_details)
        left_frame.bind("<Button-1>", toggle_details)
        right_frame.bind("<Button-1>", toggle_details)
        name_label.bind("<Button-1>", toggle_details)
        yara_thq_label.bind("<Button-1>", toggle_details)
        info_label.bind("<Button-1>", toggle_details)
        expand_indicator.bind("<Button-1>", toggle_details)
    
    def populate_file_details(self, parent_frame, file_info):
        """Populate the detailed information section"""
        # Create a text widget for better formatting
        details_text_frame = ctk.CTkFrame(parent_frame, fg_color="gray10")
        details_text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        details_text = self.case_manager.format_file_details(file_info)

        # Use text widget for selectable text
        text_widget = tk.Text(
            details_text_frame,
            wrap="none",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.monospace(10),
            height=12,
            relief="flat",
            padx=10,
            pady=10,
            cursor="arrow"
        )

        # Configure tag for clickable links
        text_widget.tag_config("link", foreground="#4a9eff", underline=True)
        text_widget.tag_bind("link", "<Enter>", lambda e: text_widget.config(cursor="hand2"))
        text_widget.tag_bind("link", "<Leave>", lambda e: text_widget.config(cursor="arrow"))

        # Insert the text
        text_widget.insert("1.0", details_text)

        # Find and tag VT link if present
        vt_link = file_info.get('vt_link', '')
        if vt_link and vt_link != 'N/A':
            # Search for the VT link in the text
            start_pos = "1.0"
            while True:
                start_pos = text_widget.search(vt_link, start_pos, tk.END)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(vt_link)}c"
                text_widget.tag_add("link", start_pos, end_pos)

                # Bind click to open in browser
                def open_link(event, url=vt_link):
                    webbrowser.open(url)
                    return "break"

                text_widget.tag_bind("link", "<Button-1>", open_link)
                start_pos = end_pos

        text_widget.configure(state="disabled")  # Make read-only
        text_widget.pack(fill="both", expand=True)

    def delete_file_from_case(self, file_info, card_frame):
        """
        Delete a file from the current case.

        Args:
            file_info: Dictionary containing file information
            card_frame: The GUI frame/card to remove
        """
        try:
            file_path = file_info.get('storage_path', '')
            file_name = file_info['filename']

            # Remove file from disk
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
                print(f"✓ Deleted file: {file_path}")

                # Also remove the _details.json file
                details_path = file_path + "_details.json"
                if os.path.exists(details_path):
                    os.remove(details_path)

                # Remove decoded file if exists
                decoded_path = file_path + "_decoded.txt"
                if os.path.exists(decoded_path):
                    os.remove(decoded_path)

            # Remove from current case files list
            if file_info in self.current_case["files"]:
                self.current_case["files"].remove(file_info)

            # Update case statistics
            if not file_info.get("whitelisted", False):
                # Subtract YARA matches
                yara_matches = file_info.get("yara_matches", [])
                if yara_matches:
                    self.current_case["files_with_yara"] = max(0, self.current_case.get("files_with_yara", 0) - 1)

                # Subtract THQ family
                thq_family = file_info.get("thq_family", "")
                if thq_family and thq_family not in ["Unknown", "N/A"]:
                    self.current_case["files_with_thq"] = max(0, self.current_case.get("files_with_thq", 0) - 1)

                # Subtract VT hits
                vt_hits = file_info.get("vt_hits", 0)
                if vt_hits > 0:
                    self.current_case["files_with_vt"] = max(0, self.current_case.get("files_with_vt", 0) - 1)
                    self.current_case["total_vt_hits"] = max(0, self.current_case.get("total_vt_hits", 0) - vt_hits)

            # Save updated case metadata
            if self.current_case and self.current_case.get("id"):
                case_dir = os.path.join(self.case_manager.case_storage_path, self.current_case["id"])
                self.case_manager.save_case_metadata(case_dir, self.current_case)

            # Remove the card from display
            card_frame.destroy()

            # Update stats display
            self.update_current_case_display()

            # Show success message
            messagebox.showinfo("File Deleted", f"Successfully deleted {file_name} from the case.")

        except Exception as e:
            messagebox.showerror("Delete Error", f"Failed to delete file:\n\n{str(e)}")
            print(f"Error deleting file: {e}")
    # ==================== YARA RULES TAB ====================
    def create_yara_rules_tab(self):
        """Create the YARA Rules Management tab"""
        frame = ctk.CTkFrame(self.content_area, fg_color=self.colors["dark_blue"])
        self.tabs["yara_rules"] = frame

        # Header
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)

        title = ctk.CTkLabel(header_frame, text="YARA Rules Management",
                            font=Fonts.header_subsection,
                            text_color="white")
        title.pack(side="left")

        # Action buttons
        btn_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_frame.pack(side="right")

        btn_add_rule = ctk.CTkButton(btn_frame, text="+ Add Rule",
                                     command=self.add_yara_rule_dialog,
                                     fg_color=self.colors["red"],
                                     hover_color=self.colors["red_dark"],
                                     font=Fonts.label_large)
        btn_add_rule.pack(side="left", padx=5)

        btn_import_rule = ctk.CTkButton(btn_frame, text="Import from File",
                                       command=self.import_yara_rule_file,
                                       fg_color=self.colors["navy"],
                                       hover_color=self.colors["dark_blue"],
                                       font=Fonts.label_large)
        btn_import_rule.pack(side="left", padx=5)

        btn_refresh = ctk.CTkButton(btn_frame, text="Refresh",
                                   command=self.refresh_yara_rules_list,
                                   fg_color=self.colors["navy"],
                                   hover_color=self.colors["dark_blue"],
                                   font=Fonts.label_large)
        btn_refresh.pack(side="left", padx=5)

        # Info bar
        info_frame = ctk.CTkFrame(frame, fg_color=self.colors["navy"], height=50)
        info_frame.pack(fill="x", padx=20, pady=(0, 10))
        info_frame.pack_propagate(False)

        self.yara_rules_count_label = ctk.CTkLabel(info_frame,
                                                   text="Total Rules: 0",
                                                   font=Fonts.label_large,
                                                   text_color="white")
        self.yara_rules_count_label.pack(side="left", padx=20, pady=10)

        path_label = ctk.CTkLabel(info_frame,
                                 text=f"Location: {self.case_manager.yara_rules_path}",
                                 font=Fonts.label,
                                 text_color="#cccccc")
        path_label.pack(side="left", padx=20, pady=10)

        # Rules list container with scrollbar
        list_container = ctk.CTkFrame(frame, fg_color=self.colors["navy"])
        list_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Create Treeview for efficient display of many rules
        # Style configuration for dark theme
        style = ttk.Style()
        style.theme_use('default')
        style.configure("Yara.Treeview",
                       background="#1a2332",
                       foreground="white",
                       fieldbackground="#1a2332",
                       borderwidth=0,
                       font=('Segoe UI', 11))
        style.configure("Yara.Treeview.Heading",
                       background="#0d1520",
                       foreground="white",
                       borderwidth=0,
                       font=('Segoe UI', 12, 'bold'))
        style.map('Yara.Treeview',
                 background=[('selected', '#991b1b')])

        # Create treeview with scrollbar
        tree_frame = tk.Frame(list_container, bg="#1a2332")
        tree_frame.pack(fill="both", expand=True, padx=2, pady=2)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side="bottom", fill="x")

        # Treeview
        self.yara_rules_tree = ttk.Treeview(
            tree_frame,
            columns=("name", "size", "modified"),
            show="headings",
            style="Yara.Treeview",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            selectmode="browse"
        )

        vsb.config(command=self.yara_rules_tree.yview)
        hsb.config(command=self.yara_rules_tree.xview)

        # Configure columns with sorting
        self.yara_rules_tree.heading("name", text="Rule Filename ▼", anchor="w",
                                     command=lambda: self.sort_yara_tree("name"))
        self.yara_rules_tree.heading("size", text="Size (bytes)", anchor="center",
                                     command=lambda: self.sort_yara_tree("size"))
        self.yara_rules_tree.heading("modified", text="Last Modified", anchor="center",
                                     command=lambda: self.sort_yara_tree("modified"))

        self.yara_rules_tree.column("name", width=300, anchor="w")
        self.yara_rules_tree.column("size", width=120, anchor="center")
        self.yara_rules_tree.column("modified", width=200, anchor="center")

        self.yara_rules_tree.pack(fill="both", expand=True)

        # Context menu for rule actions
        self.yara_context_menu = tk.Menu(self.root, tearoff=0, bg="#0d1520", fg="white",
                                         activebackground="#991b1b", activeforeground="white")
        self.yara_context_menu.add_command(label="View Rule", command=self.view_selected_yara_rule)
        self.yara_context_menu.add_command(label="Edit Rule", command=self.edit_selected_yara_rule)
        self.yara_context_menu.add_separator()
        self.yara_context_menu.add_command(label="Delete Rule", command=self.delete_selected_yara_rule)

        # Bind right-click
        self.yara_rules_tree.bind("<Button-3>", self.show_yara_context_menu)

        # Bind double-click to view
        self.yara_rules_tree.bind("<Double-1>", lambda e: self.view_selected_yara_rule())

        # Action buttons below the table
        action_frame = ctk.CTkFrame(frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=10)

        btn_view = ctk.CTkButton(action_frame, text="View",
                                command=self.view_selected_yara_rule,
                                fg_color=self.colors["navy"],
                                hover_color=self.colors["dark_blue"],
                                font=Fonts.label_large,
                                width=100)
        btn_view.pack(side="left", padx=5)

        btn_edit = ctk.CTkButton(action_frame, text="Edit",
                                command=self.edit_selected_yara_rule,
                                fg_color=self.colors["navy"],
                                hover_color=self.colors["dark_blue"],
                                font=Fonts.label_large,
                                width=100)
        btn_edit.pack(side="left", padx=5)

        btn_delete = ctk.CTkButton(action_frame, text="Delete",
                                  command=self.delete_selected_yara_rule,
                                  fg_color=self.colors["red"],
                                  hover_color=self.colors["red_dark"],
                                  font=Fonts.label_large,
                                  width=100)
        btn_delete.pack(side="left", padx=5)

        # Initialize sort state
        self.yara_sort_column = "name"
        self.yara_sort_reverse = False

    def sort_yara_tree(self, column):
        """Sort treeview by column"""
        # Toggle sort direction if clicking same column
        if self.yara_sort_column == column:
            self.yara_sort_reverse = not self.yara_sort_reverse
        else:
            self.yara_sort_column = column
            self.yara_sort_reverse = False

        # Get all items
        items = [(self.yara_rules_tree.item(item, "values"), item)
                 for item in self.yara_rules_tree.get_children("")]

        # Determine sort key based on column
        if column == "name":
            col_idx = 0
            key_func = lambda x: x[0][col_idx].lower()
        elif column == "size":
            col_idx = 1
            key_func = lambda x: int(x[0][col_idx].replace(",", "")) if x[0][col_idx] else 0
        elif column == "modified":
            col_idx = 2
            key_func = lambda x: x[0][col_idx]

        # Sort items
        items.sort(key=key_func, reverse=self.yara_sort_reverse)

        # Rearrange items in treeview
        for idx, (values, item) in enumerate(items):
            self.yara_rules_tree.move(item, "", idx)

        # Update column headers with sort indicator
        for col in ["name", "size", "modified"]:
            header_text = {
                "name": "Rule Filename",
                "size": "Size (bytes)",
                "modified": "Last Modified"
            }[col]

            if col == column:
                arrow = " ▼" if self.yara_sort_reverse else " ▲"
                header_text += arrow

            self.yara_rules_tree.heading(col, text=header_text)

    def refresh_yara_rules_list(self):
        """Refresh the list of YARA rules - optimized for large lists"""
        # Clear existing items
        for item in self.yara_rules_tree.get_children():
            self.yara_rules_tree.delete(item)

        # Get list of rules
        rules = self.yara_rule_manager.list_rules()

        # Update count
        self.yara_rules_count_label.configure(text=f"Total Rules: {len(rules)}")

        if not rules:
            # Insert a message item
            self.yara_rules_tree.insert("", "end", values=("No YARA rules found", "", ""))
            return

        # Insert all rules into treeview (very fast even with 100+ rules)
        for rule in rules:
            self.yara_rules_tree.insert(
                "",
                "end",
                values=(
                    rule["name"],
                    f"{rule['size']:,}",
                    rule['modified'].strftime('%Y-%m-%d %H:%M:%S')
                ),
                tags=(rule["name"],)  # Store rule name in tags for easy retrieval
            )

    def show_yara_context_menu(self, event):
        """Show context menu on right-click"""
        # Select the item under cursor
        item = self.yara_rules_tree.identify_row(event.y)
        if item:
            self.yara_rules_tree.selection_set(item)
            self.yara_context_menu.post(event.x_root, event.y_root)

    def get_selected_yara_rule(self):
        """Get the currently selected rule from the tree"""
        selection = self.yara_rules_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule first")
            return None

        item = selection[0]
        values = self.yara_rules_tree.item(item, "values")
        if not values or values[0] == "No YARA rules found":
            return None

        # Return rule dict with the necessary info
        return {
            "name": values[0],
            "size": int(values[1].replace(",", "")),
            "modified": None  # Not needed for operations
        }

    def view_selected_yara_rule(self):
        """View the selected rule"""
        rule = self.get_selected_yara_rule()
        if rule:
            self.view_yara_rule(rule)

    def edit_selected_yara_rule(self):
        """Edit the selected rule"""
        rule = self.get_selected_yara_rule()
        if rule:
            self.edit_yara_rule(rule)

    def delete_selected_yara_rule(self):
        """Delete the selected rule"""
        rule = self.get_selected_yara_rule()
        if rule:
            self.delete_yara_rule(rule)

    def add_yara_rule_dialog(self):
        """Show dialog to add a new YARA rule"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Add YARA Rule")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Header
        header = ctk.CTkLabel(dialog, text="Create New YARA Rule",
                             font=Fonts.header_subsection)
        header.pack(pady=20)

        # Rule name input
        name_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        name_frame.pack(fill="x", padx=20, pady=10)

        name_label = ctk.CTkLabel(name_frame, text="Rule Filename:",
                                 font=Fonts.label_large)
        name_label.pack(side="left", padx=10)

        name_entry = ctk.CTkEntry(name_frame, placeholder_text="example.yara",
                                 font=Fonts.label_large, width=300)
        name_entry.pack(side="left", padx=10)

        # Rule content text area
        content_label = ctk.CTkLabel(dialog, text="Rule Content:",
                                    font=Fonts.label_large)
        content_label.pack(anchor="w", padx=30, pady=(10, 5))

        content_frame = ctk.CTkFrame(dialog)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        content_text.pack(fill="both", expand=True)

        # Add example template
        example_rule = """rule Example_Rule
{
    meta:
        author = "Your Name"
        description = "Description of what this rule detects"

    strings:
        $string1 = "suspicious string" ascii wide
        $string2 = { 6A 40 68 00 30 00 00 }

    condition:
        any of them
}"""
        content_text.insert("1.0", example_rule)

        # Validation status
        status_label = ctk.CTkLabel(dialog, text="",
                                   font=Fonts.label,
                                   text_color="yellow")
        status_label.pack(pady=5)

        # Buttons
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=20)

        def validate_and_add():
            rule_name = name_entry.get().strip()
            rule_content = content_text.get("1.0", "end-1c").strip()

            if not rule_name:
                status_label.configure(text="Please enter a rule filename",
                                      text_color="red")
                return

            if not rule_content:
                status_label.configure(text="Please enter rule content",
                                      text_color="red")
                return

            # Validate rule syntax
            is_valid, error_msg = self.yara_rule_manager.validate_yara_rule(rule_content)
            if not is_valid:
                status_label.configure(text=f"Validation failed: {error_msg}",
                                      text_color="red")
                return

            # Add the rule
            success, message = self.yara_rule_manager.add_rule_from_content(rule_name, rule_content)
            if success:
                messagebox.showinfo("Success", message)
                dialog.destroy()
                self.refresh_yara_rules_list()
                # Reload YARA rules in case manager
                self.case_manager.load_yara_rules()
            else:
                status_label.configure(text=f"Error: {message}",
                                      text_color="red")

        btn_validate = ctk.CTkButton(btn_frame, text="Validate",
                                    command=lambda: self.validate_rule_content(content_text, status_label),
                                    fg_color=self.colors["navy"],
                                    hover_color=self.colors["dark_blue"],
                                    font=Fonts.label_large)
        btn_validate.pack(side="left", padx=5)

        btn_add = ctk.CTkButton(btn_frame, text="Add Rule",
                               command=validate_and_add,
                               fg_color=self.colors["red"],
                               hover_color=self.colors["red_dark"],
                               font=Fonts.label_large)
        btn_add.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(btn_frame, text="Cancel",
                                  command=dialog.destroy,
                                  fg_color="gray",
                                  font=Fonts.label_large)
        btn_cancel.pack(side="left", padx=5)

    def validate_rule_content(self, text_widget, status_label):
        """Validate YARA rule content"""
        rule_content = text_widget.get("1.0", "end-1c").strip()
        is_valid, error_msg = self.yara_rule_manager.validate_yara_rule(rule_content)

        if is_valid:
            status_label.configure(text="✓ Rule syntax is valid",
                                  text_color="green")
        else:
            status_label.configure(text=f"✗ {error_msg}",
                                  text_color="red")

    def import_yara_rule_file(self):
        """Import a YARA rule from a file"""
        file_path = filedialog.askopenfilename(
            title="Select YARA Rule File",
            filetypes=[("YARA Rules", "*.yara *.yar"), ("All Files", "*.*")]
        )

        if not file_path:
            return

        success, message = self.yara_rule_manager.add_rule_from_file(file_path)
        if success:
            messagebox.showinfo("Success", message)
            self.refresh_yara_rules_list()
            # Reload YARA rules in case manager
            self.case_manager.load_yara_rules()
        else:
            messagebox.showerror("Error", message)

    def view_yara_rule(self, rule):
        """View a YARA rule in a read-only dialog"""
        success, content = self.yara_rule_manager.get_rule_content(rule["name"])
        if not success:
            messagebox.showerror("Error", content)
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"View Rule: {rule['name']}")
        dialog.geometry("800x600")
        dialog.transient(self.root)

        # Header
        header = ctk.CTkLabel(dialog, text=rule["name"],
                             font=Fonts.header_subsection)
        header.pack(pady=20)

        # Content display
        content_frame = ctk.CTkFrame(dialog)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        content_text.pack(fill="both", expand=True)
        content_text.insert("1.0", content)
        content_text.configure(state="disabled")

        # Close button
        btn_close = ctk.CTkButton(dialog, text="Close",
                                 command=dialog.destroy,
                                 font=Fonts.label_large)
        btn_close.pack(pady=20)

    def edit_yara_rule(self, rule):
        """Edit an existing YARA rule"""
        success, content = self.yara_rule_manager.get_rule_content(rule["name"])
        if not success:
            messagebox.showerror("Error", content)
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"Edit Rule: {rule['name']}")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Header
        header = ctk.CTkLabel(dialog, text=f"Editing: {rule['name']}",
                             font=Fonts.header_subsection)
        header.pack(pady=20)

        # Content editor
        content_frame = ctk.CTkFrame(dialog)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        content_text.pack(fill="both", expand=True)
        content_text.insert("1.0", content)

        # Validation status
        status_label = ctk.CTkLabel(dialog, text="",
                                   font=Fonts.label)
        status_label.pack(pady=5)

        # Buttons
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=20)

        def save_changes():
            new_content = content_text.get("1.0", "end-1c").strip()

            # Validate
            is_valid, error_msg = self.yara_rule_manager.validate_yara_rule(new_content)
            if not is_valid:
                status_label.configure(text=f"Validation failed: {error_msg}",
                                      text_color="red")
                return

            # Update with backup setting from settings
            create_backup = self.settings_manager.get("yara.create_backups_on_update", True)
            success, message = self.yara_rule_manager.update_rule(rule["name"], new_content, create_backup=create_backup)
            if success:
                messagebox.showinfo("Success", message)
                dialog.destroy()
                self.refresh_yara_rules_list()
                # Reload YARA rules in case manager
                self.case_manager.load_yara_rules()
            else:
                status_label.configure(text=f"Error: {message}",
                                      text_color="red")

        btn_validate = ctk.CTkButton(btn_frame, text="Validate",
                                    command=lambda: self.validate_rule_content(content_text, status_label),
                                    fg_color=self.colors["navy"],
                                    font=Fonts.label_large)
        btn_validate.pack(side="left", padx=5)

        btn_save = ctk.CTkButton(btn_frame, text="Save Changes",
                                command=save_changes,
                                fg_color=self.colors["red"],
                                hover_color=self.colors["red_dark"],
                                font=Fonts.label_large)
        btn_save.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(btn_frame, text="Cancel",
                                  command=dialog.destroy,
                                  fg_color="gray",
                                  font=Fonts.label_large)
        btn_cancel.pack(side="left", padx=5)

    def delete_yara_rule(self, rule):
        """Delete a YARA rule"""
        # Check if backups are enabled in settings
        create_backup = self.settings_manager.get("yara.create_backups_on_delete", True)

        backup_msg = "\n\nA backup will be created automatically." if create_backup else ""
        result = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete '{rule['name']}'?{backup_msg}"
        )

        if not result:
            return

        success, message = self.yara_rule_manager.delete_rule(rule["name"], create_backup=create_backup)
        if success:
            messagebox.showinfo("Success", message)
            self.refresh_yara_rules_list()
            # Reload YARA rules in case manager
            self.case_manager.load_yara_rules()
        else:
            messagebox.showerror("Error", message)

    # ==================== SETTINGS TAB ====================
    def create_settings_tab(self):
        """Create the Settings tab"""
        frame = ctk.CTkFrame(self.content_area, fg_color=self.colors["dark_blue"])
        self.tabs["settings"] = frame

        # Header
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)

        title = ctk.CTkLabel(header_frame, text="Application Settings",
                            font=Fonts.header_subsection,
                            text_color="white")
        title.pack(side="left")

        # Action buttons
        btn_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_frame.pack(side="right")

        btn_save = ctk.CTkButton(btn_frame, text="Save Settings",
                                command=self.save_settings,
                                fg_color=self.colors["red"],
                                hover_color=self.colors["red_dark"],
                                font=Fonts.label_large)
        btn_save.pack(side="left", padx=5)

        btn_reset = ctk.CTkButton(btn_frame, text="Reset to Defaults",
                                 command=self.reset_settings,
                                 fg_color=self.colors["navy"],
                                 hover_color=self.colors["dark_blue"],
                                 font=Fonts.label_large)
        btn_reset.pack(side="left", padx=5)

        # Scrollable settings container
        settings_scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        settings_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Store entry widgets for later access
        self.settings_widgets = {}

        # API Keys Section
        self.create_settings_section(settings_scroll, "API Keys", [
            ("api_keys.virustotal", "VirusTotal API Key", "entry"),
            ("api_keys.threathq_user", "ThreatHQ Username", "entry"),
            ("api_keys.threathq_pass", "ThreatHQ Password", "entry"),
        ])

        # Analysis Settings
        self.create_settings_section(settings_scroll, "Analysis Settings", [
            ("analysis.enable_process_monitoring", "Enable Process Monitoring", "switch"),
            ("analysis.enable_network_monitoring", "Enable Network Monitoring", "switch"),
            ("analysis.enable_yara_scanning", "Enable YARA Scanning", "switch"),
            ("analysis.auto_scan_new_processes", "Auto-scan New Processes", "switch"),
            ("analysis.enable_realtime_alerts", "Enable Real-time Alerts", "switch"),
        ])

        # UI Settings
        self.create_settings_section(settings_scroll, "User Interface", [
            ("application.theme", "Theme", "option", ["dark", "light"]),
            ("application.auto_refresh_interval", "Auto-refresh Interval (ms)", "entry"),
            ("application.max_popups_per_rule", "Max Alerts per Rule", "entry"),
            ("ui.show_welcome_screen", "Show Welcome Screen", "switch"),
            ("ui.confirm_before_delete", "Confirm Before Delete", "switch"),
            ("ui.enable_tooltips", "Enable Tooltips", "switch"),
        ])

        # YARA Settings
        self.create_settings_section(settings_scroll, "YARA Settings", [
            ("yara.create_backups_on_delete", "Create Backups on Delete", "switch"),
            ("yara.create_backups_on_update", "Create Backups on Update", "switch"),
        ])

        # Export Settings
        self.create_settings_section(settings_scroll, "Export Settings", [
            ("export.default_export_format", "Default Export Format", "option", ["json", "csv"]),
            ("export.include_metadata", "Include Metadata", "switch"),
            ("export.include_hashes", "Include File Hashes", "switch"),
        ])

        # Advanced Settings
        self.create_settings_section(settings_scroll, "Advanced", [
            ("advanced.debug_mode", "Debug Mode", "switch"),
            ("advanced.log_file", "Log Filename", "entry"),
            ("advanced.max_log_size_mb", "Max Log Size (MB)", "entry"),
        ])

        # Network Settings
        self.create_settings_section(settings_scroll, "Network Sharing", [
            ("network.analyst_name", "Analyst Name", "entry"),
            ("network.enable_network_case_folder", "Enable Network Case Folder", "switch"),
            ("network.network_case_folder_path", "Network Case Folder Path", "entry"),
            ("network.enable_network_yara_sync", "Enable Network YARA Sync", "switch"),
            ("network.network_yara_path", "Network YARA Path", "entry"),
        ])

        # Load current settings
        self.load_settings_to_ui()

    def create_settings_section(self, parent, section_name, settings_list):
        """Create a settings section with multiple settings"""
        # Section header
        section_frame = ctk.CTkFrame(parent, fg_color=self.colors["navy"],
                                    corner_radius=10)
        section_frame.pack(fill="x", pady=10, padx=10)

        header = ctk.CTkLabel(section_frame, text=section_name,
                             font=Fonts.label_large,
                             text_color="white")
        header.pack(anchor="w", padx=20, pady=15)

        # Settings items
        for setting_info in settings_list:
            key_path = setting_info[0]
            label_text = setting_info[1]
            widget_type = setting_info[2]
            options = setting_info[3] if len(setting_info) > 3 else None

            self.create_setting_item(section_frame, key_path, label_text, widget_type, options)

    def create_setting_item(self, parent, key_path, label_text, widget_type, options=None):
        """Create a single setting item"""
        item_frame = ctk.CTkFrame(parent, fg_color="transparent")
        item_frame.pack(fill="x", padx=20, pady=5)

        # Label
        label = ctk.CTkLabel(item_frame, text=label_text,
                            font=Fonts.label_large,
                            text_color="white",
                            width=300,
                            anchor="w")
        label.pack(side="left", padx=10)

        # Widget based on type
        if widget_type == "entry":
            widget = ctk.CTkEntry(item_frame, font=Fonts.label_large, width=300)
            widget.pack(side="right", padx=10, pady=5)
        elif widget_type == "switch":
            widget = ctk.CTkSwitch(item_frame, text="", font=Fonts.label_large)
            widget.pack(side="right", padx=10, pady=5)
        elif widget_type == "option" and options:
            widget = ctk.CTkOptionMenu(item_frame, values=options,
                                      font=Fonts.label_large, width=200)
            widget.pack(side="right", padx=10, pady=5)
        else:
            return

        # Store widget reference
        self.settings_widgets[key_path] = widget

    def load_settings_to_ui(self):
        """Load settings from manager into UI widgets"""
        for key_path, widget in self.settings_widgets.items():
            value = self.settings_manager.get(key_path)

            if isinstance(widget, ctk.CTkEntry):
                widget.delete(0, "end")
                widget.insert(0, str(value) if value is not None else "")
            elif isinstance(widget, ctk.CTkSwitch):
                if value:
                    widget.select()
                else:
                    widget.deselect()
            elif isinstance(widget, ctk.CTkOptionMenu):
                widget.set(str(value))

    def save_settings(self):
        """Save settings from UI to settings manager"""
        for key_path, widget in self.settings_widgets.items():
            if isinstance(widget, ctk.CTkEntry):
                value = widget.get()
                # Try to convert to appropriate type
                try:
                    # Try int first
                    if value.isdigit():
                        value = int(value)
                    elif value.replace('.', '', 1).isdigit():
                        value = float(value)
                except:
                    pass  # Keep as string
                self.settings_manager.set(key_path, value)
            elif isinstance(widget, ctk.CTkSwitch):
                value = widget.get() == 1
                self.settings_manager.set(key_path, value)
            elif isinstance(widget, ctk.CTkOptionMenu):
                value = widget.get()
                self.settings_manager.set(key_path, value)

        # Save to file
        if self.settings_manager.save_settings():
            # Apply settings immediately
            self.apply_settings()
            messagebox.showinfo("Success", "Settings saved and applied successfully.\n\nNote: API key changes will take effect for new operations.")
        else:
            messagebox.showerror("Error", "Failed to save settings")

    def apply_settings(self):
        """Apply settings to the running application"""
        # Apply UI settings
        self.auto_refresh_interval = self.settings_manager.get("application.auto_refresh_interval", 2000)
        self.max_popups_per_rule = self.settings_manager.get("application.max_popups_per_rule", 3)

        # Update API keys in case manager (for new operations)
        vt_api_key = self.settings_manager.get("api_keys.virustotal")
        threathq_user = self.settings_manager.get("api_keys.threathq_user")
        threathq_pass = self.settings_manager.get("api_keys.threathq_pass")

        if vt_api_key:
            self.case_manager.vt_api_key = vt_api_key
        if threathq_user:
            self.case_manager.threathq_user = threathq_user
        if threathq_pass:
            self.case_manager.threathq_pass = threathq_pass

        print("Settings applied successfully")

    def reset_settings(self):
        """Reset settings to defaults"""
        result = messagebox.askyesno(
            "Confirm Reset",
            "Are you sure you want to reset all settings to defaults?\n\nThis action cannot be undone."
        )

        if not result:
            return

        if self.settings_manager.reset_to_defaults():
            self.load_settings_to_ui()
            self.apply_settings()
            messagebox.showinfo("Success", "Settings reset to defaults and applied")
        else:
            messagebox.showerror("Error", "Failed to reset settings")

    # ==================== APPLICATION LIFECYCLE ====================
    def run(self):
        """Start the application"""
        # Auto-start process monitoring
        if not self.process_monitor_active:
            self.process_monitor.start_monitoring()
            self.process_monitor_active = True
            # Update button text if it exists
            if hasattr(self, 'btn_toggle_process_monitor'):
                self.btn_toggle_process_monitor.configure(text="⏸ Stop Monitoring")
            # Start auto-refresh
            self.start_auto_refresh()

        self.root.mainloop()

    # ==================== PROCESS MONITOR METHODS ====================
    def toggle_process_monitoring(self):
        """Toggle process monitoring on/off"""
        if not self.process_monitor_active:
            self.process_monitor.start_monitoring()
            self.process_monitor_active = True
            self.btn_toggle_process_monitor.configure(text="⏸ Stop Monitoring")
            # Start auto-refresh when monitoring starts
            self.start_auto_refresh()
            messagebox.showinfo("Monitoring Active",
                              "Process monitoring started. New processes will be automatically scanned with YARA.")
        else:
            self.process_monitor.stop_monitoring()
            self.process_monitor_active = False
            self.btn_toggle_process_monitor.configure(text="▶ Start Monitoring")
            # Stop auto-refresh when monitoring stops
            self.stop_auto_refresh()

    def start_auto_refresh(self):
        """Start automatic process tree refresh"""
        if not self.auto_refresh_enabled:
            return

        # Cancel any existing job
        if self.auto_refresh_job:
            self.root.after_cancel(self.auto_refresh_job)

        # Schedule next refresh
        def auto_refresh_callback():
            if self.process_monitor_active and self.auto_refresh_enabled:
                self.refresh_process_list()
                self.auto_refresh_job = self.root.after(self.auto_refresh_interval, auto_refresh_callback)

        self.auto_refresh_job = self.root.after(self.auto_refresh_interval, auto_refresh_callback)

    def stop_auto_refresh(self):
        """Stop automatic process tree refresh"""
        if self.auto_refresh_job:
            self.root.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None
    
    def refresh_process_list(self):
        """Refresh the process tree with parent-child hierarchy using incremental updates"""
        # Check if a filter is active - if so, use filter_processes instead
        search_text = self.process_search_entry.get().strip() if hasattr(self, 'process_search_entry') else ""
        filter_choice = self.process_filter_var.get() if hasattr(self, 'process_filter_var') else "All Processes"

        # If any filter is active, delegate to filter_processes to maintain filtered view
        if search_text or filter_choice != "All Processes":
            self.filter_processes()
            return

        # Get all current processes
        processes = self.process_monitor.get_all_processes()

        # Build process map by PID
        process_map = {proc['pid']: proc for proc in processes}
        current_pids = set(process_map.keys())
        existing_pids = set(self.pid_to_tree_item.keys())

        # Determine what changed
        pids_to_add = current_pids - existing_pids  # PIDs that need to be added to tree
        dead_pids = existing_pids - current_pids
        potentially_updated_pids = current_pids & existing_pids

        # Only mark as "new" (yellow highlight) if this is not the initial load
        if self.process_tree_initial_load:
            new_pids = set()  # Don't highlight any as new on initial load
        else:
            new_pids = pids_to_add  # After initial load, newly added PIDs are truly new

        # Save expanded and selected state
        expanded_pids = set()
        selected_pid = None

        for pid in existing_pids:
            if pid in self.pid_to_tree_item:
                item_id = self.pid_to_tree_item[pid]
                try:
                    if self.process_tree.exists(item_id):
                        if self.process_tree.item(item_id, 'open'):
                            expanded_pids.add(pid)
                except:
                    pass

        selection = self.process_tree.selection()
        if selection:
            try:
                values = self.process_tree.item(selection[0], 'values')
                if values and len(values) > 0:
                    selected_pid = int(values[0])
            except:
                pass

        # Remove dead processes
        for pid in dead_pids:
            if pid in self.pid_to_tree_item:
                try:
                    self.process_tree.delete(self.pid_to_tree_item[pid])
                except:
                    pass
                del self.pid_to_tree_item[pid]

        # Update existing processes (check if YARA status changed)
        for pid in potentially_updated_pids:
            if pid not in self.pid_to_tree_item:
                continue

            proc = process_map[pid]
            item_id = self.pid_to_tree_item[pid]

            try:
                if not self.process_tree.exists(item_id):
                    # Item was deleted, need to re-add
                    new_pids.add(pid)
                    del self.pid_to_tree_item[pid]
                    continue

                # Check if YARA status changed
                current_values = self.process_tree.item(item_id, 'values')

                # Check if process is suspended
                is_suspended = False
                try:
                    import psutil
                    process_status = psutil.Process(pid).status()
                    is_suspended = process_status == psutil.STATUS_STOPPED
                except:
                    pass

                # Determine new YARA status
                yara_status = "No"
                tags = ()
                if is_suspended:
                    yara_status = "⏸️ SUSPENDED"
                    tags = ('suspended',)
                elif proc.get('threat_detected'):
                    yara_rule = proc.get('yara_rule', 'Unknown')
                    if yara_rule and yara_rule != 'Unknown':
                        # Check if there are multiple rules
                        scan_results = proc.get('scan_results', {})
                        all_rules = scan_results.get('all_rules', [yara_rule])
                        if len(all_rules) > 1:
                            yara_status = f"⚠️ {yara_rule} +{len(all_rules) - 1}"
                        else:
                            yara_status = f"⚠️ {yara_rule}"
                    else:
                        matches = proc.get('yara_matches', 0)
                        yara_status = f"⚠️ {matches} matches" if matches else "⚠️ YES"
                    tags = ('threat',)
                elif proc.get('whitelisted', False):
                    yara_status = "✅ BENIGN"
                    tags = ('benign',)
                elif pid in new_pids:
                    tags = ('new',)
                elif proc['name'].lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                    tags = ('system',)

                # Update if YARA status changed
                if len(current_values) > 3 and current_values[3] != yara_status:
                    self.process_tree.item(item_id, values=(pid, proc['name'], proc.get('exe', 'N/A'), yara_status), tags=tags)
            except Exception as e:
                # If error, mark for re-adding
                if pid in self.pid_to_tree_item:
                    del self.pid_to_tree_item[pid]
                pids_to_add.add(pid)
                if not self.process_tree_initial_load:
                    new_pids.add(pid)  # Also mark as new if not initial load

        # Add new processes - use full rebuild for new processes to maintain hierarchy
        if pids_to_add:
            # Build parent-child relationships for all processes
            children_map = {}
            root_processes = []

            for proc in processes:
                ppid = proc.get('ppid')
                if ppid and ppid in process_map and ppid != proc['pid']:
                    if ppid not in children_map:
                        children_map[ppid] = []
                    children_map[ppid].append(proc)
                else:
                    root_processes.append(proc)

            # Recursive function to add process and children
            def add_process_tree(proc, parent_id=""):
                pid = proc['pid']

                # Skip if already in tree
                if pid in self.pid_to_tree_item:
                    try:
                        if self.process_tree.exists(self.pid_to_tree_item[pid]):
                            # Already exists, just recurse to children
                            if pid in children_map:
                                for child in children_map[pid]:
                                    add_process_tree(child, self.pid_to_tree_item[pid])
                            return
                    except:
                        pass

                name = proc['name']
                exe = proc.get('exe', 'N/A')

                # Check if process is suspended
                is_suspended = False
                try:
                    import psutil
                    process_status = psutil.Process(pid).status()
                    is_suspended = process_status == psutil.STATUS_STOPPED
                except:
                    pass

                # Determine YARA match status
                yara_status = "No"
                tags = ()
                if is_suspended:
                    yara_status = "⏸️ SUSPENDED"
                    tags = ('suspended',)
                elif proc.get('threat_detected'):
                    yara_rule = proc.get('yara_rule', 'Unknown')
                    if yara_rule and yara_rule != 'Unknown':
                        # Check if there are multiple rules
                        scan_results = proc.get('scan_results', {})
                        all_rules = scan_results.get('all_rules', [yara_rule])
                        if len(all_rules) > 1:
                            yara_status = f"⚠️ {yara_rule} +{len(all_rules) - 1}"
                        else:
                            yara_status = f"⚠️ {yara_rule}"
                    else:
                        matches = proc.get('yara_matches', 0)
                        yara_status = f"⚠️ {matches} matches" if matches else "⚠️ YES"
                    tags = ('threat',)
                elif proc.get('whitelisted', False):
                    yara_status = "✅ BENIGN"
                    tags = ('benign',)
                elif pid in new_pids:
                    tags = ('new',)
                elif name.lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                    tags = ('system',)

                # Insert into tree
                item_id = self.process_tree.insert(
                    parent_id,
                    "end",
                    text=f"  {name}",
                    values=(pid, name, exe, yara_status),
                    tags=tags,
                    open=pid in expanded_pids
                )

                # Store mapping
                self.pid_to_tree_item[pid] = item_id

                # Add children recursively
                if pid in children_map:
                    for child in children_map[pid]:
                        add_process_tree(child, item_id)

            # Add new root processes and their trees
            for proc in root_processes:
                if proc['pid'] in pids_to_add or proc['pid'] not in self.pid_to_tree_item:
                    add_process_tree(proc)

            # Add any remaining new child processes that weren't added as part of root process trees
            # This handles the case where a new child process appears under an existing parent
            remaining_new_pids = [pid for pid in pids_to_add if pid not in self.pid_to_tree_item]
            for pid in remaining_new_pids:
                if pid in process_map:
                    proc = process_map[pid]
                    ppid = proc.get('ppid')

                    # Find the parent in the tree
                    parent_item_id = ""
                    if ppid and ppid in self.pid_to_tree_item:
                        try:
                            if self.process_tree.exists(self.pid_to_tree_item[ppid]):
                                parent_item_id = self.pid_to_tree_item[ppid]
                        except:
                            pass

                    # Add the process under its parent (or as root if parent not found)
                    add_process_tree(proc, parent_item_id)

        # Restore selection
        if selected_pid and selected_pid in self.pid_to_tree_item:
            try:
                self.process_tree.selection_set(self.pid_to_tree_item[selected_pid])
                self.process_tree.see(self.pid_to_tree_item[selected_pid])
            except:
                pass

        # Mark initial load as complete
        if self.process_tree_initial_load:
            self.process_tree_initial_load = False

    def focus_process_by_pid(self, target_pid):
        """
        Focus on a specific process in the tree by PID, expanding parents as needed.

        Args:
            target_pid: PID of the process to focus on
        """
        try:
            # Check if PID exists in tree
            if target_pid not in self.pid_to_tree_item:
                print(f"PID {target_pid} not found in process tree yet")
                # Try refreshing and checking again after a delay
                self.refresh_process_tree()
                self.root.after(1000, lambda: self.focus_process_by_pid(target_pid))
                return

            item_id = self.pid_to_tree_item[target_pid]

            # Expand all parent items
            parent = self.process_tree.parent(item_id)
            while parent:
                self.process_tree.item(parent, open=True)
                parent = self.process_tree.parent(parent)

            # Select and scroll to the item
            self.process_tree.selection_set(item_id)
            self.process_tree.see(item_id)
            self.process_tree.focus(item_id)

            print(f"✓ Focused on process PID {target_pid}")

        except Exception as e:
            print(f"Error focusing on PID {target_pid}: {e}")

    def should_show_popup(self, rule_name):
        """
        Determine if a popup should be shown for this YARA rule.
        Limits popups to max_popups_per_rule per rule family to reduce alert fatigue.
        Returns True if popup should be shown, False if limit reached.
        """
        if not rule_name or rule_name == 'No_YARA_Hit':
            return False

        # Get current count for this rule
        count = self.popup_count_by_rule.get(rule_name, 0)

        if count < self.max_popups_per_rule:
            # Increment counter and show popup
            self.popup_count_by_rule[rule_name] = count + 1
            return True
        else:
            # Limit reached, suppress popup
            print(f"ℹ️  Popup suppressed for {rule_name} (limit: {self.max_popups_per_rule} per rule)")
            return False

    def update_yara_match_badge(self):
        """
        Update the YARA match counter badge with current count and color coding.
        Color scheme: yellow (1-10), orange (11-25), red (26+)
        """
        count = self.total_yara_matches

        # Update text
        self.yara_match_badge.configure(text=f"⚠️ YARA: {count}")

        # Color code based on count
        if count == 0:
            # Gray for no matches
            self.yara_match_badge.configure(
                text_color="#9ca3af",
                fg_color="#374151"
            )
        elif count <= 10:
            # Yellow for low count
            self.yara_match_badge.configure(
                text_color="#fbbf24",
                fg_color="#78350f"
            )
        elif count <= 25:
            # Orange for medium count
            self.yara_match_badge.configure(
                text_color="#fb923c",
                fg_color="#7c2d12"
            )
        else:
            # Red for high count
            self.yara_match_badge.configure(
                text_color="#f87171",
                fg_color="#7f1d1d"
            )

    def filter_processes(self):
        """Filter processes by PID or Name, showing matching processes and all their children"""
        search_text = self.process_search_entry.get().strip().lower()
        filter_choice = self.process_filter_var.get() if hasattr(self, 'process_filter_var') else "All Processes"

        # If no filters applied, refresh to show all
        if not search_text and filter_choice == "All Processes":
            # Mark that we're doing a filter clear rebuild - don't highlight as new
            # Store current PIDs to preserve history
            known_pids_before_clear = set(self.pid_to_tree_item.keys())

            # Clear the tree to ensure full rebuild when switching from filtered to unfiltered view
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            self.pid_to_tree_item.clear()

            # Temporarily set initial load flag to prevent yellow highlighting during rebuild
            was_initial_load = self.process_tree_initial_load
            self.process_tree_initial_load = True

            self.refresh_process_list()

            # Restore the flag immediately after refresh
            self.process_tree_initial_load = was_initial_load
            return

        # Get all processes
        processes = self.process_monitor.get_all_processes()
        process_map = {proc['pid']: proc for proc in processes}

        # Build parent-child relationships
        children_map = {}
        for proc in processes:
            ppid = proc.get('ppid')
            if ppid and ppid in process_map and ppid != proc['pid']:
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(proc)

        # Find matching processes (by PID, Name, and Filter)
        matching_pids = set()
        for proc in processes:
            pid_str = str(proc['pid'])
            name_lower = proc['name'].lower()

            # Check search text
            search_match = not search_text or (search_text in pid_str or search_text in name_lower)

            # Check filter
            filter_match = True
            if filter_choice == "YARA Matches Only":
                yara_rule = proc.get('yara_rule')
                filter_match = (proc.get('threat_detected', False) and
                               yara_rule and
                               yara_rule != 'No_YARA_Hit')
            elif filter_choice == "Benign Only":
                filter_match = proc.get('whitelisted', False)
            elif filter_choice == "Not Scanned":
                filter_match = not proc.get('threat_detected', False) and not proc.get('whitelisted', False)

            # Add if both conditions match
            if search_match and filter_match:
                matching_pids.add(proc['pid'])

        # Recursively get all children of matching processes
        def get_all_children(pid):
            """Recursively get all children PIDs"""
            child_pids = set()
            if pid in children_map:
                for child in children_map[pid]:
                    child_pid = child['pid']
                    child_pids.add(child_pid)
                    child_pids.update(get_all_children(child_pid))
            return child_pids

        # Add all children of matching processes
        pids_to_show = set(matching_pids)
        for pid in matching_pids:
            pids_to_show.update(get_all_children(pid))

        # Clear the tree
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        self.pid_to_tree_item.clear()

        # Build filtered tree
        def add_process_to_tree(proc, parent_id=""):
            """Add process to tree with hierarchy"""
            pid = proc['pid']
            name = proc['name']
            exe = proc.get('exe', 'N/A')

            # Determine YARA match status
            yara_status = "No"
            tags = ()
            if proc.get('threat_detected'):
                yara_rule = proc.get('yara_rule', 'Unknown')
                if yara_rule and yara_rule != 'Unknown':
                    # Check if there are multiple rules
                    scan_results = proc.get('scan_results', {})
                    all_rules = scan_results.get('all_rules', [yara_rule])
                    if len(all_rules) > 1:
                        yara_status = f"⚠️ {yara_rule} +{len(all_rules) - 1}"
                    else:
                        yara_status = f"⚠️ {yara_rule}"
                else:
                    matches = proc.get('yara_matches', 0)
                    yara_status = f"⚠️ {matches} matches" if matches else "⚠️ YES"
                tags = ('threat',)
            elif name.lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                tags = ('system',)

            # Insert into tree (expanded by default for filtered view)
            item_id = self.process_tree.insert(
                parent_id,
                "end",
                text=f"  {name}",
                values=(pid, name, exe, yara_status),
                tags=tags,
                open=True  # Auto-expand
            )

            self.pid_to_tree_item[pid] = item_id

            # Add children recursively if they should be shown
            if pid in children_map:
                for child in children_map[pid]:
                    if child['pid'] in pids_to_show:
                        add_process_to_tree(child, item_id)

        # Add all filtered processes (root level only, children will be added recursively)
        root_pids = []
        for pid in pids_to_show:
            if pid in process_map:
                proc = process_map[pid]
                ppid = proc.get('ppid')
                # Check if parent is also in filtered set
                if ppid not in pids_to_show or ppid not in process_map or ppid == proc['pid']:
                    root_pids.append(pid)

        # Sort and add root processes
        for pid in sorted(root_pids):
            if pid in process_map:
                add_process_to_tree(process_map[pid])

    def clear_process_search(self):
        """Clear the process search and show all processes"""
        self.process_search_entry.delete(0, tk.END)
        self.refresh_process_list()

    def get_child_pids_recursive(self, parent_pid):
        """Get all child PIDs recursively for a given parent PID"""
        child_pids = set()

        # Get all processes
        processes = self.process_monitor.get_all_processes()

        # Build parent-child map
        children_map = {}
        for proc in processes:
            ppid = proc.get('ppid')
            if ppid:
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(proc['pid'])

        # Recursive function to get all children
        def get_children(pid):
            if pid in children_map:
                for child_pid in children_map[pid]:
                    child_pids.add(child_pid)
                    get_children(child_pid)  # Recurse to get children of children

        get_children(parent_pid)
        return child_pids

    def show_process_context_menu(self, event):
        """Show right-click context menu for processes"""
        try:
            # Get selected process
            selection = self.process_tree.selection()
            if not selection:
                return

            # Check if process is suspended
            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            is_suspended = False

            try:
                import psutil
                process_status = psutil.Process(pid).status()
                is_suspended = process_status == psutil.STATUS_STOPPED
            except:
                pass

            # Remove any existing suspend/resume entries
            # The menu structure is: Scan, View Details, Open Folder, Separator, [Suspend/Resume], Kill
            # So suspend/resume would be at index 4 (after separator at 3)
            menu_length = self.process_context_menu.index('end')
            if menu_length is not None and menu_length >= 4:
                # Check if there's a suspend or resume entry
                try:
                    label = self.process_context_menu.entrycget(4, 'label')
                    if '⏸️' in label or '▶️' in label:
                        self.process_context_menu.delete(4)
                except:
                    pass

            # Add appropriate menu item
            if is_suspended:
                # Show Resume option
                self.process_context_menu.insert_command(
                    4,
                    label="▶️ Resume Process",
                    command=self.resume_selected_process
                )
            else:
                # Show Suspend option
                self.process_context_menu.insert_command(
                    4,
                    label="⏸️ Suspend Process",
                    command=self.suspend_selected_process
                )

            self.process_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.process_context_menu.grab_release()
    
    def scan_selected_process(self):
        """Scan selected process with YARA"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to scan")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])

        # Scan in thread
        def scan():
            result = self.process_monitor.scan_process(pid)
            if 'error' in result:
                self.root.after(0, lambda: messagebox.showerror("Scan Error", result['error']))
            else:
                matches_found = result.get('matches_found', False)
                rule = result.get('rule', 'No_YARA_Hit')
                threat_score = result.get('threat_score', 0)
                risk_level = result.get('risk_level', 'Low')
                strings = result.get('strings', [])

                # Update monitored_processes dictionary so YARA Matches column is updated
                if pid not in self.process_monitor.monitored_processes:
                    # Get process info first
                    try:
                        proc = __import__('psutil').Process(pid)
                        self.process_monitor.monitored_processes[pid] = {
                            'pid': pid,
                            'name': proc.name(),
                            'exe': proc.exe() if proc.exe() else "N/A",
                            'scan_results': result,
                            'threat_detected': matches_found,
                            'yara_rule': rule if matches_found else None
                        }
                    except:
                        # If process info fails, just store scan results
                        self.process_monitor.monitored_processes[pid] = {
                            'pid': pid,
                            'scan_results': result,
                            'threat_detected': matches_found,
                            'yara_rule': rule if matches_found else None
                        }
                else:
                    # Update existing entry
                    self.process_monitor.monitored_processes[pid]['scan_results'] = result
                    self.process_monitor.monitored_processes[pid]['threat_detected'] = matches_found
                    self.process_monitor.monitored_processes[pid]['yara_rule'] = rule if matches_found else None

                # If threats detected, show red warning popup like live scan
                if matches_found and rule != 'No_YARA_Hit':
                    # Increment total YARA match count
                    self.total_yara_matches += 1

                    # Update the badge display
                    self.root.after(0, self.update_yara_match_badge)

                    # Check if we should show popup (limits to 3 per rule family)
                    if not self.should_show_popup(rule):
                        # Popup suppressed, but match still counted and visible in filter
                        # Refresh list to show the match
                        self.root.after(0, self.refresh_process_list)
                        return

                    def show_threat_alert():
                        # Get process info for the alert
                        try:
                            proc = __import__('psutil').Process(pid)
                            proc_name = proc.name()
                            proc_exe = proc.exe() if proc.exe() else "N/A"
                        except:
                            proc_name = "Unknown"
                            proc_exe = "N/A"

                        alert = ctk.CTkToplevel(self.root)
                        alert.title("⚠️ Threat Detected")
                        alert.geometry("700x650")
                        alert.minsize(600, 500)
                        alert.attributes('-topmost', True)

                        # Main container frame
                        main_frame = ctk.CTkFrame(alert, fg_color=self.colors["red_dark"])
                        main_frame.pack(fill="both", expand=True, padx=2, pady=2)

                        # Header section
                        header_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                        header_frame.pack(fill="x", padx=10, pady=(15, 10))

                        title = ctk.CTkLabel(
                            header_frame,
                            text="⚠️ MALICIOUS PROCESS DETECTED",
                            font=Fonts.title_large,
                            text_color="white"
                        )
                        title.pack()

                        # Content section (scrollable)
                        content_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

                        # Get all matched rules
                        all_rules = result.get('all_rules', [rule])
                        rules_display = ', '.join(all_rules) if len(all_rules) > 1 else rule

                        # Details section
                        details_frame = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                        details_frame.pack(fill="x", padx=10, pady=10)

                        details = f"""PID: {pid}
Name: {proc_name}
Path: {proc_exe}

YARA Rule(s): {rules_display}
Threat Score: {threat_score}
Risk Level: {risk_level}"""

                        details_label = ctk.CTkLabel(
                            details_frame,
                            text=details,
                            font=Fonts.body,
                            justify="left",
                            text_color="white"
                        )
                        details_label.pack(pady=15, padx=15, anchor="w")

                        # Matched strings section
                        if strings:
                            strings_header = ctk.CTkLabel(
                                content_frame,
                                text=f"Matched Strings ({len(strings)}):",
                                font=Fonts.body_bold,
                                text_color="white"
                            )
                            strings_header.pack(pady=(5, 5), padx=10, anchor="w")

                            # Scrollable strings container with fixed height
                            strings_container = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                            strings_container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

                            strings_frame = ctk.CTkScrollableFrame(
                                strings_container,
                                fg_color="#2b2b2b",
                                height=250
                            )
                            strings_frame.pack(fill="both", expand=True, padx=5, pady=5)

                            # Display all strings
                            for i, s in enumerate(strings, 1):
                                s_display = s[:100] + "..." if len(s) > 100 else s
                                string_label = ctk.CTkLabel(
                                    strings_frame,
                                    text=f"{i}. {s_display}",
                                    font=Fonts.helper,
                                    text_color="white",
                                    anchor="w",
                                    justify="left"
                                )
                                string_label.pack(anchor="w", pady=2, padx=5, fill="x")

                        # Footer with close button (always visible)
                        footer_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                        footer_frame.pack(fill="x", padx=10, pady=(5, 15))

                        btn_close = ctk.CTkButton(
                            footer_frame,
                            text="Close",
                            command=alert.destroy,
                            fg_color=self.colors["navy"],
                            hover_color=self.colors["dark_blue"],
                            width=120,
                            height=35
                        )
                        btn_close.pack(pady=5)

                    self.root.after(0, show_threat_alert)
                else:
                    # No threats, show simple info popup
                    msg = f"PID {pid} Scan Complete\n\nNo threats detected."
                    self.root.after(0, lambda: messagebox.showinfo("Scan Results", msg))

                self.root.after(0, self.refresh_process_list)

        threading.Thread(target=scan, daemon=True).start()

    def scan_all_processes(self):
        """Scan all processes with YARA"""
        # Confirm action
        if not messagebox.askyesno("Confirm Scan All",
                                   "This will scan ALL running processes. This may take some time.\n\nContinue?"):
            return

        # Get all processes
        processes = self.process_monitor.get_all_processes()
        total_processes = len(processes)

        # Create progress window
        progress_window = ctk.CTkToplevel(self.root)
        progress_window.title("Scanning Processes")
        progress_window.geometry("500x200")
        progress_window.attributes('-topmost', True)

        frame = ctk.CTkFrame(progress_window, fg_color="gray20")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        title_label = ctk.CTkLabel(
            frame,
            text="Scanning All Processes",
            font=Fonts.title_medium,
            text_color="white"
        )
        title_label.pack(pady=10)

        progress_label = ctk.CTkLabel(
            frame,
            text=f"Scanning process 0 of {total_processes}",
            font=Fonts.body,
            text_color="white"
        )
        progress_label.pack(pady=10)

        progress_bar = ctk.CTkProgressBar(frame, width=400)
        progress_bar.pack(pady=10)
        progress_bar.set(0)

        stats_label = ctk.CTkLabel(
            frame,
            text="Threats found: 0 | Benign: 0 | Errors: 0",
            font=Fonts.helper,
            text_color="white"
        )
        stats_label.pack(pady=10)

        # Scan statistics
        scan_stats = {
            'scanned': 0,
            'threats': 0,
            'benign': 0,
            'errors': 0
        }

        # Scan in background thread
        def scan_all():
            for i, proc in enumerate(processes):
                pid = proc['pid']

                # Update progress
                self.root.after(0, lambda i=i: progress_label.configure(
                    text=f"Scanning PID {pid} ({i+1} of {total_processes})"
                ))
                self.root.after(0, lambda i=i: progress_bar.set((i + 1) / total_processes))

                # Scan process
                try:
                    result = self.process_monitor.scan_process(pid)

                    if 'error' not in result:
                        matches_found = result.get('matches_found', False)
                        rule = result.get('rule', 'No_YARA_Hit')

                        # Update monitored_processes
                        if pid not in self.process_monitor.monitored_processes:
                            self.process_monitor.monitored_processes[pid] = {
                                'pid': pid,
                                'name': proc['name'],
                                'exe': proc.get('exe', 'N/A'),
                                'scan_results': result,
                                'threat_detected': matches_found,
                                'yara_rule': rule if matches_found else None
                            }
                        else:
                            self.process_monitor.monitored_processes[pid]['scan_results'] = result
                            self.process_monitor.monitored_processes[pid]['threat_detected'] = matches_found
                            self.process_monitor.monitored_processes[pid]['yara_rule'] = rule if matches_found else None

                        # Update stats
                        if matches_found and rule != 'No_YARA_Hit':
                            scan_stats['threats'] += 1
                        else:
                            scan_stats['benign'] += 1
                    else:
                        scan_stats['errors'] += 1

                    scan_stats['scanned'] += 1

                    # Update stats display
                    self.root.after(0, lambda: stats_label.configure(
                        text=f"Threats found: {scan_stats['threats']} | Benign: {scan_stats['benign']} | Errors: {scan_stats['errors']}"
                    ))

                except Exception as e:
                    scan_stats['errors'] += 1
                    print(f"[ERROR] Failed to scan PID {pid}: {e}")

            # Scan complete
            self.root.after(0, lambda: progress_label.configure(text="Scan Complete!"))
            self.root.after(0, self.refresh_process_list)

            # Show summary
            summary_msg = f"""Scan Complete!

Total Scanned: {scan_stats['scanned']}
Threats Detected: {scan_stats['threats']}
Benign Processes: {scan_stats['benign']}
Errors: {scan_stats['errors']}"""

            self.root.after(0, lambda: messagebox.showinfo("Scan Complete", summary_msg))
            self.root.after(0, progress_window.destroy)

        threading.Thread(target=scan_all, daemon=True).start()

    # FIXED: Combined view_process_details and extract_strings into one method
    def view_process_details_and_strings(self):
        """View detailed process information and extracted strings in a unified window"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to view")
            return
        
        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['values'][1]
        
        # Get process info
        info = self.process_monitor.get_process_info(pid)
        if not info:
            messagebox.showerror("Error", f"Could not get info for PID {pid}")
            return
        
        # Create window
        details_window = ctk.CTkToplevel(self.root)
        details_window.title(f"Process Analysis: {name} (PID {pid})")
        details_window.geometry("1000x700")
        
        # Main container
        main_container = ctk.CTkFrame(details_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)
        
        title = ctk.CTkLabel(
            header,
            text=f"🔍 {name} (PID {pid})",
            font=Fonts.logo_subtitle
        )
        title.pack(side="left", padx=20, pady=15)
        
        # Tab buttons
        tab_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        tab_frame.pack(fill="x", padx=0, pady=(0, 10))
        
        btn_info = ctk.CTkButton(
            tab_frame,
            text="📋 Process Info",
            command=lambda: show_tab("info"),
            height=35,
            width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        btn_info.pack(side="left", padx=5)
        
        btn_strings = ctk.CTkButton(
            tab_frame,
            text="📄 Strings",
            command=lambda: show_tab("strings"),
            height=35,
            width=150,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"]
        )
        btn_strings.pack(side="left", padx=5)

        btn_events = ctk.CTkButton(
            tab_frame,
            text="📊 Live Events",
            command=lambda: show_tab("events"),
            height=35,
            width=150,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"]
        )
        btn_events.pack(side="left", padx=5)
        
        # Content area
        content_area = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        content_area.pack(fill="both", expand=True)
        
        # ===== INFO TAB =====
        info_frame = ctk.CTkFrame(content_area, fg_color="transparent")
        
        # Format details
        details = f"""Process Details (PID {pid})
{'='*80}

Name: {info['name']}
Executable: {info['exe']}
Command Line: {info['cmdline']}
Status: {info['status']}
Username: {info['username']}
Created: {info['create_time']}
Parent PID: {info['parent_pid']} ({info['parent_name']})

"""
        
        if 'cpu_percent' in info:
            details += f"CPU: {info['cpu_percent']:.1f}%\n"
        if 'memory_info' in info:
            details += f"Memory (RSS): {info['memory_info']['rss'] / 1024 / 1024:.2f} MB\n"
        if 'num_threads' in info:
            details += f"Threads: {info['num_threads']}\n"
        
        if info.get('connections'):
            details += f"\nNetwork Connections: {len(info['connections'])}\n"
            details += "="*80 + "\n"
            for conn in info['connections'][:10]:
                details += f"  {conn['laddr']} -> {conn['raddr']} ({conn['status']})\n"
        
        # Check if YARA scanned
        if pid in self.process_monitor.monitored_processes:
            scan_results = self.process_monitor.monitored_processes[pid].get('scan_results', {})
            if scan_results.get('matches_found'):
                details += f"\n{'='*80}\n"
                details += "⚠️ YARA SCAN RESULTS\n"
                details += f"{'='*80}\n"

                # Show all matched rules
                all_rules = scan_results.get('all_rules', [scan_results.get('rule', 'Unknown')])
                if len(all_rules) > 1:
                    details += f"Rules Matched ({len(all_rules)}):\n"
                    for i, rule in enumerate(all_rules, 1):
                        details += f"  {i}. {rule}\n"
                else:
                    details += f"Rule Matched: {all_rules[0]}\n"

                details += f"Threat Score: {scan_results.get('threat_score', 0)}\n"
                details += f"Risk Level: {scan_results.get('risk_level', 'Unknown')}\n"

                # Show all matched strings
                if scan_results.get('strings'):
                    details += f"\nMatched Strings ({len(scan_results['strings'])}):\n"
                    for i, s in enumerate(scan_results['strings'], 1):
                        details += f"  {i}. {s}\n"
        
        info_text = tk.Text(
            info_frame,
            wrap="word",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.monospace(11),
            relief="flat",
            padx=20,
            pady=20
        )
        info_text.insert("1.0", details)
        info_text.configure(state="disabled")
        info_text.pack(fill="both", expand=True, padx=2, pady=2)
        
        # ===== STRINGS TAB =====
        strings_frame = ctk.CTkFrame(content_area, fg_color="transparent")

        # Search and filter controls
        search_frame = ctk.CTkFrame(strings_frame, fg_color=self.colors["navy"], height=90)
        search_frame.pack(fill="x", padx=10, pady=10)
        search_frame.pack_propagate(False)

        # First row: Search
        search_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        search_row.pack(fill="x", padx=5, pady=(5, 0))

        search_label = ctk.CTkLabel(
            search_row,
            text="🔍 Search:",
            font=Fonts.body_bold
        )
        search_label.pack(side="left", padx=(10, 5))

        search_entry = ctk.CTkEntry(
            search_row,
            width=300,
            height=35,
            placeholder_text="Enter search term...",
            font=Fonts.body
        )
        search_entry.pack(side="left", padx=5)

        # Status label
        status_label = ctk.CTkLabel(
            search_row,
            text="Extracting strings...",
            font=Fonts.helper,
            text_color="gray60"
        )
        status_label.pack(side="left", padx=20)

        # Second row: Length filter, quality filter toggle, and refresh button
        filter_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=5, pady=(5, 5))

        # Length filter
        length_label = ctk.CTkLabel(
            filter_row,
            text="📏 Length:",
            font=Fonts.body_bold
        )
        length_label.pack(side="left", padx=(10, 5))

        min_label = ctk.CTkLabel(
            filter_row,
            text="Min:",
            font=Fonts.helper
        )
        min_label.pack(side="left", padx=(5, 2))

        min_length_entry = ctk.CTkEntry(
            filter_row,
            width=60,
            height=30,
            placeholder_text="4",
            font=Fonts.helper
        )
        min_length_entry.insert(0, "4")
        min_length_entry.pack(side="left", padx=2)

        max_label = ctk.CTkLabel(
            filter_row,
            text="Max:",
            font=Fonts.helper
        )
        max_label.pack(side="left", padx=(10, 2))

        max_length_entry = ctk.CTkEntry(
            filter_row,
            width=60,
            height=30,
            placeholder_text="∞",
            font=Fonts.helper
        )
        max_length_entry.pack(side="left", padx=2)

        # Quality filter toggle
        quality_filter_var = ctk.BooleanVar(value=True)
        quality_filter_checkbox = ctk.CTkCheckBox(
            filter_row,
            text="Quality Filter",
            variable=quality_filter_var,
            font=Fonts.helper,
            checkbox_width=20,
            checkbox_height=20
        )
        quality_filter_checkbox.pack(side="left", padx=15)

        # Quick Scan button (default)
        quick_scan_btn = ctk.CTkButton(
            filter_row,
            text="⚡ Quick Scan",
            command=lambda: None,  # Will be set later
            height=30,
            width=120,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label
        )
        quick_scan_btn.pack(side="left", padx=5)

        # Deep Scan button
        deep_scan_btn = ctk.CTkButton(
            filter_row,
            text="🔬 Deep Scan",
            command=lambda: None,  # Will be set later
            height=30,
            width=120,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"],
            font=Fonts.label
        )
        deep_scan_btn.pack(side="left", padx=5)

        # Export button
        export_btn = ctk.CTkButton(
            filter_row,
            text="💾 Export TXT",
            command=lambda: None,  # Will be set later
            height=30,
            width=120,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"],
            font=Fonts.label
        )
        export_btn.pack(side="left", padx=5)
        
        # Strings text area
        strings_text_frame = ctk.CTkFrame(strings_frame, fg_color="gray20")
        strings_text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        vsb = tk.Scrollbar(strings_text_frame, orient="vertical", bg="#1a1a1a")
        vsb.pack(side="right", fill="y")
        
        hsb = tk.Scrollbar(strings_text_frame, orient="horizontal", bg="#1a1a1a")
        hsb.pack(side="bottom", fill="x")
        
        strings_text = tk.Text(
            strings_text_frame,
            wrap="none",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.monospace(10),
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        strings_text.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        vsb.config(command=strings_text.yview)
        hsb.config(command=strings_text.xview)
        
        # Store original strings and extraction result for export
        all_strings_data = {"strings": [], "original_text": "", "extraction_result": None, "current_mode": "quick"}

        def search_strings(event=None):
            """Search and highlight strings with length filtering"""
            search_term = search_entry.get().strip().lower()

            # Get length filter values
            try:
                min_len = int(min_length_entry.get()) if min_length_entry.get() else 0
            except ValueError:
                min_len = 0

            try:
                max_len = int(max_length_entry.get()) if max_length_entry.get() else float('inf')
            except ValueError:
                max_len = float('inf')

            strings_text.configure(state="normal")
            strings_text.delete("1.0", "end")

            # Apply length filter first
            length_filtered = [s for s in all_strings_data["strings"] if min_len <= len(s) <= max_len]

            if not search_term:
                # Show all strings (with length filter applied)
                if length_filtered:
                    display_text = "\n".join(length_filtered[:1000])  # Limit display for performance
                    strings_text.insert("1.0", display_text)
                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (filtered by length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
                    status_label.configure(text=f"Showing: {len(length_filtered)} strings{filter_msg}")
                else:
                    strings_text.insert("1.0", "No strings match the length filter")
                    status_label.configure(text="No matches")
            else:
                # Filter by search term and length
                filtered = [s for s in length_filtered if search_term in s.lower()]

                if filtered:
                    for s in filtered[:1000]:  # Limit for performance
                        # Highlight search term
                        lower_s = s.lower()
                        start_idx = 0
                        display_line = s + "\n"
                        strings_text.insert("end", display_line)

                        # Find and tag matches
                        while True:
                            pos = lower_s.find(search_term, start_idx)
                            if pos == -1:
                                break

                            # Calculate text widget position
                            line_num = int(strings_text.index("end").split(".")[0]) - 1
                            tag_start = f"{line_num}.{pos}"
                            tag_end = f"{line_num}.{pos + len(search_term)}"
                            strings_text.tag_add("highlight", tag_start, tag_end)
                            start_idx = pos + len(search_term)

                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
                    status_label.configure(text=f"Found: {len(filtered)} matches{filter_msg}")
                else:
                    strings_text.insert("1.0", f"No strings found matching '{search_term}' with current filters")
                    status_label.configure(text="No matches")

            # Configure highlight tag
            strings_text.tag_config("highlight", background=self.colors["red"], foreground="white")
            strings_text.configure(state="disabled")

        search_entry.bind("<KeyRelease>", search_strings)
        min_length_entry.bind("<KeyRelease>", search_strings)
        max_length_entry.bind("<KeyRelease>", search_strings)

        # Re-extract when quality filter changes
        def on_quality_filter_change():
            """Re-extract strings when quality filter setting changes"""
            # Re-extract with current mode
            threading.Thread(target=lambda: extract(all_strings_data["current_mode"]), daemon=True).start()

        quality_filter_checkbox.configure(command=on_quality_filter_change)

        # Extract strings in background with progressive loading
        def extract(scan_mode="quick"):
            try:
                # Store current scan mode
                all_strings_data["current_mode"] = scan_mode

                # Update button states
                if scan_mode == "quick":
                    self.root.after(0, lambda: quick_scan_btn.configure(
                        fg_color=self.colors["red"], text="⚡ Scanning..."))
                    self.root.after(0, lambda: deep_scan_btn.configure(
                        fg_color="transparent", text="🔬 Deep Scan"))
                else:
                    self.root.after(0, lambda: deep_scan_btn.configure(
                        fg_color=self.colors["red"], text="🔬 Scanning..."))
                    self.root.after(0, lambda: quick_scan_btn.configure(
                        fg_color="transparent", text="⚡ Quick Scan"))

                self.root.after(0, lambda: export_btn.configure(state="disabled"))
                status_label.configure(text=f"Extracting strings ({scan_mode} mode)...")

                # Get minimum length for extraction
                try:
                    extract_min_length = int(min_length_entry.get()) if min_length_entry.get() else 4
                    extract_min_length = max(4, min(extract_min_length, 10))
                except ValueError:
                    extract_min_length = 4

                # Get quality filter setting
                use_quality_filter = quality_filter_var.get()

                # Progressive callback for UI updates
                def progress_callback(current_strings, regions_total, regions_read, final=False):
                    """Update UI with progressive results"""
                    try:
                        # Flatten strings for display
                        flat_strings = []
                        for category_strings in current_strings.values():
                            if isinstance(category_strings, list):
                                flat_strings.extend(category_strings)

                        # Update status
                        status_msg = f"{scan_mode.capitalize()} scan: {len(flat_strings)} strings | {regions_read}/{regions_total} regions"
                        if final:
                            status_msg = f"Complete: {len(flat_strings)} strings ({scan_mode} mode)"

                        self.root.after(0, lambda msg=status_msg: status_label.configure(text=msg))

                        # Update display every 10 regions or on final
                        if final or regions_read % 10 == 0:
                            all_strings_data["strings"] = flat_strings
                            self.root.after(0, search_strings)
                    except Exception as e:
                        print(f"Progress callback error: {e}")

                # Extract with scan_mode and progressive callback - get full result with metadata
                extraction_result = self.process_monitor.extract_strings_from_process(
                    pid,
                    min_length=extract_min_length,
                    limit=20000,
                    enable_quality_filter=use_quality_filter,
                    scan_mode=scan_mode,
                    progress_callback=progress_callback,
                    return_full_result=True  # Get full result with metadata
                )

                # Extract strings list from result
                strings = extraction_result.get('strings', [])

                result_text = ""

                # Group strings by type
                urls = [s for s in strings if ('http://' in s or 'https://' in s or 'www.' in s)]
                ips = [s for s in strings if any(c.isdigit() and '.' in s for c in s)]
                paths = [s for s in strings if ('\\' in s or '/' in s) and len(s) > 10]
                others = [s for s in strings if s not in urls and s not in ips and s not in paths]

                if urls:
                    result_text += f"URLs/Domains ({len(urls)}):\n" + "="*80 + "\n"
                    result_text += "\n".join(urls[:50]) + "\n\n"
                if ips:
                    result_text += f"IP Addresses ({len(ips)}):\n" + "="*80 + "\n"
                    result_text += "\n".join(ips[:50]) + "\n\n"
                if paths:
                    result_text += f"File Paths ({len(paths)}):\n" + "="*80 + "\n"
                    result_text += "\n".join(paths[:50]) + "\n\n"
                if others:
                    result_text += f"Other Strings ({len(others)}):\n" + "="*80 + "\n"
                    result_text += "\n".join(others[:200]) + "\n"

                # Store strings and full extraction result for export
                all_strings_data["strings"] = strings
                all_strings_data["original_text"] = result_text
                all_strings_data["extraction_result"] = extraction_result  # Store full result with metadata

                # Update UI in main thread
                filter_status = "Quality Filtered" if use_quality_filter else "All Strings (Unfiltered)"
                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", result_text))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: status_label.configure(
                    text=f"Complete: {len(strings)} strings ({scan_mode} mode, {filter_status})"
                ))

                # Restore button states
                if scan_mode == "quick":
                    self.root.after(0, lambda: quick_scan_btn.configure(
                        fg_color=self.colors["red"], text="⚡ Quick Scan"))
                else:
                    self.root.after(0, lambda: deep_scan_btn.configure(
                        fg_color=self.colors["red"], text="🔬 Deep Scan"))

                self.root.after(0, lambda: export_btn.configure(state="normal"))

                # Auto-apply current filters after extraction
                self.root.after(100, search_strings)

            except Exception as e:
                import traceback
                traceback.print_exc()

                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", f"Error: {str(e)}"))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: status_label.configure(text="Error extracting strings"))

                # Restore button states
                if scan_mode == "quick":
                    self.root.after(0, lambda: quick_scan_btn.configure(text="⚡ Quick Scan"))
                else:
                    self.root.after(0, lambda: deep_scan_btn.configure(text="🔬 Deep Scan"))

                self.root.after(0, lambda: export_btn.configure(state="normal"))

        def export_strings():
            """Export extracted strings to TXT file"""
            try:
                if not all_strings_data["strings"]:
                    messagebox.showwarning("No Strings", "No strings available to export. Please run a scan first.")
                    return

                # Ask user for save location
                from tkinter import filedialog
                default_name = f"{name}_{pid}_strings_{all_strings_data['current_mode']}.txt"
                file_path = filedialog.asksaveasfilename(
                    title="Export Strings",
                    defaultextension=".txt",
                    initialfile=default_name,
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )

                if not file_path:
                    return

                # Use the real extraction result if available, otherwise create one
                if "extraction_result" in all_strings_data and all_strings_data["extraction_result"]:
                    extraction_result = all_strings_data["extraction_result"]

                    # Ensure it has the proper format for export
                    # The memory extractor expects 'strings' to be a dict of categories
                    if isinstance(extraction_result.get('strings'), list):
                        # Convert from list format to categorized format
                        strings_list = extraction_result['strings']
                        extraction_result['strings'] = {
                            'ascii': strings_list,
                            'unicode': [],
                            'urls': [s for s in strings_list if 'http' in s or 'www.' in s],
                            'paths': [s for s in strings_list if '\\' in s or '/' in s],
                            'ips': [s for s in strings_list if any(c.isdigit() and '.' in s for c in s)],
                            'registry': [],
                            'environment': []
                        }

                    # Add PID if not present
                    extraction_result['pid'] = pid
                else:
                    # Fallback: create extraction result from strings
                    extraction_result = {
                        'pid': pid,
                        'strings': {
                            'ascii': all_strings_data["strings"],
                            'unicode': [],
                            'urls': [s for s in all_strings_data["strings"] if 'http' in s or 'www.' in s],
                            'paths': [s for s in all_strings_data["strings"] if '\\' in s or '/' in s],
                            'ips': [s for s in all_strings_data["strings"] if any(c.isdigit() and '.' in s for c in s)],
                            'registry': [],
                            'environment': []
                        },
                        'scan_mode': all_strings_data['current_mode'],
                        'memory_regions': [],
                        'total_bytes_scanned': 0,
                        'errors': ['Export created without full extraction metadata']
                    }

                # Export using memory extractor's export method
                if hasattr(self.process_monitor, 'memory_extractor') and self.process_monitor.memory_extractor:
                    success = self.process_monitor.memory_extractor.export_to_txt(
                        extraction_result,
                        file_path,
                        process_name=name
                    )
                    if success:
                        # Show summary including metadata
                        mem_regions = len(extraction_result.get('memory_regions', []))
                        bytes_scanned = extraction_result.get('total_bytes_scanned', 0)
                        summary = f"Strings exported to:\n{file_path}\n\n"
                        summary += f"Memory Regions Scanned: {mem_regions}\n"
                        summary += f"Total Bytes Scanned: {bytes_scanned:,}\n"
                        summary += f"Extraction Method: {extraction_result.get('extraction_method', 'unknown')}"
                        messagebox.showinfo("Export Complete", summary)
                    else:
                        messagebox.showerror("Export Failed", "Failed to export strings")
                else:
                    messagebox.showerror("Export Failed", "Memory extractor not available")

            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting strings:\n{str(e)}")
                import traceback
                traceback.print_exc()

        # Set button commands
        quick_scan_btn.configure(command=lambda: threading.Thread(target=lambda: extract("quick"), daemon=True).start())
        deep_scan_btn.configure(command=lambda: threading.Thread(target=lambda: extract("deep"), daemon=True).start())
        export_btn.configure(command=export_strings)

        # Initial extraction (Quick Scan by default)
        threading.Thread(target=lambda: extract("quick"), daemon=True).start()

        # ===== LIVE EVENTS TAB =====
        events_frame = ctk.CTkFrame(content_area, fg_color="transparent")

        # Top controls
        controls_frame = ctk.CTkFrame(events_frame, fg_color=self.colors["navy"], height=60)
        controls_frame.pack(fill="x", padx=10, pady=10)
        controls_frame.pack_propagate(False)

        # Start/Stop monitoring button
        monitor_btn_text = tk.StringVar(value="▶ Start Monitoring")
        monitor_btn = ctk.CTkButton(
            controls_frame,
            textvariable=monitor_btn_text,
            command=None,  # Will be set later
            height=35,
            width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        monitor_btn.pack(side="left", padx=10)

        # Statistics labels
        stats_label = ctk.CTkLabel(
            controls_frame,
            text="Total: 0 | File: 0 | Network: 0 | Thread: 0 | Process: 0",
            font=Fonts.helper,
            text_color="gray60"
        )
        stats_label.pack(side="left", padx=20)

        # Export button
        export_btn = ctk.CTkButton(
            controls_frame,
            text="💾 Export",
            command=None,  # Will be set later
            height=35,
            width=100,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        export_btn.pack(side="right", padx=10)

        # Clear button
        clear_btn = ctk.CTkButton(
            controls_frame,
            text="🗑 Clear",
            command=None,  # Will be set later
            height=35,
            width=100,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        clear_btn.pack(side="right", padx=5)

        # Filter frame
        filter_frame = ctk.CTkFrame(events_frame, fg_color=self.colors["navy"], height=50)
        filter_frame.pack(fill="x", padx=10, pady=(0, 10))
        filter_frame.pack_propagate(False)

        filter_label = ctk.CTkLabel(
            filter_frame,
            text="Filter:",
            font=Fonts.body_bold
        )
        filter_label.pack(side="left", padx=10)

        # Filter buttons
        filter_var = tk.StringVar(value="All")
        filter_types = ["All", "File", "Network", "Thread", "Process", "Registry"]

        for ftype in filter_types:
            btn = ctk.CTkButton(
                filter_frame,
                text=ftype,
                command=None,  # Will be set later
                height=30,
                width=80,
                fg_color="transparent" if ftype != "All" else self.colors["red"],
                hover_color=self.colors["navy"],
                border_width=1,
                border_color=self.colors["red"]
            )
            btn.pack(side="left", padx=3)

        # Events tree view
        tree_frame = ctk.CTkFrame(events_frame, fg_color="gray20")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Scrollbars
        tree_vsb = tk.Scrollbar(tree_frame, orient="vertical", bg="#1a1a1a")
        tree_vsb.pack(side="right", fill="y")

        tree_hsb = tk.Scrollbar(tree_frame, orient="horizontal", bg="#1a1a1a")
        tree_hsb.pack(side="bottom", fill="x")

        # Create tree view for events
        columns = ("time", "type", "operation", "path", "result")
        events_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=20,
            yscrollcommand=tree_vsb.set,
            xscrollcommand=tree_hsb.set
        )

        # Configure columns
        events_tree.heading("time", text="Time")
        events_tree.heading("type", text="Type")
        events_tree.heading("operation", text="Operation")
        events_tree.heading("path", text="Path")
        events_tree.heading("result", text="Result")

        events_tree.column("time", width=100, minwidth=100)
        events_tree.column("type", width=80, minwidth=80)
        events_tree.column("operation", width=150, minwidth=100)
        events_tree.column("path", width=400, minwidth=200)
        events_tree.column("result", width=100, minwidth=80)

        # Style the tree
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                       background="#1a1a1a",
                       foreground="white",
                       fieldbackground="#1a1a1a",
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background="#0d1520",
                       foreground="white",
                       borderwidth=1)
        style.map("Treeview",
                 background=[("selected", "#dc2626")])

        events_tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        tree_vsb.config(command=events_tree.yview)
        tree_hsb.config(command=events_tree.xview)

        # Store references for event monitoring
        event_monitor_state = {
            "monitor": None,
            "monitoring": False,
            "filter": "All",
            "update_job": None
        }

        def toggle_monitoring():
            """Start/stop event monitoring for this PID"""
            if not event_monitor_state["monitoring"]:
                # Start monitoring
                try:
                    # Create and start procmon monitor
                    monitor = ProcmonLiveMonitor(pid, max_events=5000)
                    monitor.start_monitoring()

                    self.procmon_monitors[pid] = monitor
                    event_monitor_state["monitor"] = monitor
                    event_monitor_state["monitoring"] = True

                    monitor_btn_text.set("⏸ Stop Monitoring")
                    monitor_btn.configure(fg_color="#059669")  # Green

                    # Start auto-refresh
                    refresh_events()

                except Exception as e:
                    messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
            else:
                # Stop monitoring
                if event_monitor_state["monitor"]:
                    event_monitor_state["monitor"].stop_monitoring()
                    if pid in self.procmon_monitors:
                        del self.procmon_monitors[pid]

                event_monitor_state["monitoring"] = False
                event_monitor_state["monitor"] = None

                monitor_btn_text.set("▶ Start Monitoring")
                monitor_btn.configure(fg_color=self.colors["red"])

                # Cancel auto-refresh
                if event_monitor_state["update_job"]:
                    details_window.after_cancel(event_monitor_state["update_job"])
                    event_monitor_state["update_job"] = None

        def refresh_events():
            """Refresh the events display"""
            if not event_monitor_state["monitoring"] or not event_monitor_state["monitor"]:
                return

            try:
                monitor = event_monitor_state["monitor"]
                filter_type = event_monitor_state["filter"]

                # Get events
                events = monitor.get_recent_events(count=1000,
                                                  event_type=None if filter_type == "All" else filter_type)

                # Update tree
                events_tree.delete(*events_tree.get_children())

                for event in events:
                    events_tree.insert("", "end", values=(
                        event['timestamp'],
                        event['event_type'],
                        event['operation'],
                        event['path'][:80] + "..." if len(event['path']) > 80 else event['path'],
                        event['result']
                    ))

                # Update statistics
                stats = monitor.get_stats()
                stats_label.configure(
                    text=f"Total: {stats['total_events']} | "
                         f"File: {stats['file_events']} | "
                         f"Network: {stats['network_events']} | "
                         f"Thread: {stats['thread_events']} | "
                         f"Process: {stats['process_events']}"
                )

                # Schedule next refresh
                event_monitor_state["update_job"] = details_window.after(500, refresh_events)

            except Exception as e:
                print(f"Error refreshing events: {e}")

        def export_events():
            """Export events to CSV"""
            if not event_monitor_state["monitor"]:
                messagebox.showwarning("No Data", "No events to export. Start monitoring first.")
                return

            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"procmon_events_pid_{pid}.csv"
            )

            if filepath:
                try:
                    event_monitor_state["monitor"].export_events(filepath)
                    messagebox.showinfo("Success", f"Events exported to {filepath}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to export: {str(e)}")

        def clear_events():
            """Clear all events"""
            if event_monitor_state["monitor"]:
                event_monitor_state["monitor"].clear_events()
                events_tree.delete(*events_tree.get_children())
                stats_label.configure(text="Total: 0 | File: 0 | Network: 0 | Thread: 0 | Process: 0")

        def set_filter(ftype):
            """Set event filter"""
            event_monitor_state["filter"] = ftype
            # Update button colors
            for widget in filter_frame.winfo_children():
                if isinstance(widget, ctk.CTkButton) and widget.cget("text") in filter_types:
                    if widget.cget("text") == ftype:
                        widget.configure(fg_color=self.colors["red"])
                    else:
                        widget.configure(fg_color="transparent")
            refresh_events()

        # Connect button commands
        monitor_btn.configure(command=toggle_monitoring)
        export_btn.configure(command=export_events)
        clear_btn.configure(command=clear_events)

        # Connect filter buttons
        for widget in filter_frame.winfo_children():
            if isinstance(widget, ctk.CTkButton) and widget.cget("text") in filter_types:
                ftype = widget.cget("text")
                widget.configure(command=lambda f=ftype: set_filter(f))

        # Cleanup on window close
        def on_window_close():
            """Clean up when window is closed"""
            if event_monitor_state["monitoring"]:
                toggle_monitoring()
            details_window.destroy()

        details_window.protocol("WM_DELETE_WINDOW", on_window_close)

        # Tab switching
        tabs = {"info": info_frame, "strings": strings_frame, "events": events_frame}
        buttons = {"info": btn_info, "strings": btn_strings, "events": btn_events}

        def show_tab(tab_name):
            for name, frame in tabs.items():
                frame.pack_forget()

            for name, btn in buttons.items():
                if name == tab_name:
                    btn.configure(
                        fg_color=self.colors["red"],
                        border_width=0
                    )
                else:
                    btn.configure(
                        fg_color="transparent",
                        border_width=2,
                        border_color=self.colors["red"]
                    )

            tabs[tab_name].pack(fill="both", expand=True)

            # Auto-start monitoring when events tab is opened
            if tab_name == "events" and not event_monitor_state["monitoring"]:
                toggle_monitoring()

        show_tab("info")

    def view_file_strings(self, file_path, file_name):
        """View extracted strings from a static file in a dedicated window"""
        # Create window
        strings_window = ctk.CTkToplevel(self.root)
        strings_window.title(f"File Strings: {file_name}")
        strings_window.geometry("1000x700")

        # Main container
        main_container = ctk.CTkFrame(strings_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(
            header,
            text=f"📄 {file_name}",
            font=Fonts.logo_subtitle
        )
        title.pack(side="left", padx=20, pady=15)

        # Search and filter controls
        search_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=90)
        search_frame.pack(fill="x", padx=10, pady=10)
        search_frame.pack_propagate(False)

        # First row: Search
        search_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        search_row.pack(fill="x", padx=5, pady=(5, 0))

        search_label = ctk.CTkLabel(
            search_row,
            text="🔍 Search:",
            font=Fonts.body_bold
        )
        search_label.pack(side="left", padx=(10, 5))

        search_entry = ctk.CTkEntry(
            search_row,
            width=300,
            height=35,
            placeholder_text="Enter search term...",
            font=Fonts.body
        )
        search_entry.pack(side="left", padx=5)

        # Status label
        status_label = ctk.CTkLabel(
            search_row,
            text="Extracting strings...",
            font=Fonts.helper,
            text_color="gray60"
        )
        status_label.pack(side="left", padx=20)

        # Second row: Filters and buttons
        filter_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=5, pady=(5, 5))

        # Length filter
        length_label = ctk.CTkLabel(
            filter_row,
            text="📏 Length:",
            font=Fonts.body_bold
        )
        length_label.pack(side="left", padx=(10, 5))

        min_label = ctk.CTkLabel(
            filter_row,
            text="Min:",
            font=Fonts.helper
        )
        min_label.pack(side="left", padx=(5, 2))

        min_length_entry = ctk.CTkEntry(
            filter_row,
            width=60,
            height=30,
            placeholder_text="4",
            font=Fonts.helper
        )
        min_length_entry.insert(0, "4")
        min_length_entry.pack(side="left", padx=2)

        max_label = ctk.CTkLabel(
            filter_row,
            text="Max:",
            font=Fonts.helper
        )
        max_label.pack(side="left", padx=(10, 2))

        max_length_entry = ctk.CTkEntry(
            filter_row,
            width=60,
            height=30,
            placeholder_text="∞",
            font=Fonts.helper
        )
        max_length_entry.pack(side="left", padx=2)

        # Quality filter toggle
        quality_filter_var = ctk.BooleanVar(value=True)
        quality_filter_checkbox = ctk.CTkCheckBox(
            filter_row,
            text="Quality Filter",
            variable=quality_filter_var,
            font=Fonts.helper,
            checkbox_width=20,
            checkbox_height=20
        )
        quality_filter_checkbox.pack(side="left", padx=15)

        # Export button
        export_btn = ctk.CTkButton(
            filter_row,
            text="💾 Export TXT",
            command=lambda: None,  # Will be set later
            height=30,
            width=120,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label
        )
        export_btn.pack(side="left", padx=5)

        # Strings text area
        strings_text_frame = ctk.CTkFrame(main_container, fg_color="gray20")
        strings_text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        vsb = tk.Scrollbar(strings_text_frame, orient="vertical", bg="#1a1a1a")
        vsb.pack(side="right", fill="y")

        hsb = tk.Scrollbar(strings_text_frame, orient="horizontal", bg="#1a1a1a")
        hsb.pack(side="bottom", fill="x")

        strings_text = tk.Text(
            strings_text_frame,
            wrap="none",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.monospace(10),
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        strings_text.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        vsb.config(command=strings_text.yview)
        hsb.config(command=strings_text.xview)

        # Store extraction data
        extraction_data = {"strings": [], "extraction_result": None}

        def search_strings(event=None):
            """Search and filter strings"""
            search_term = search_entry.get().strip().lower()

            # Get length filter
            try:
                min_len = int(min_length_entry.get()) if min_length_entry.get() else 0
            except ValueError:
                min_len = 0

            try:
                max_len = int(max_length_entry.get()) if max_length_entry.get() else float('inf')
            except ValueError:
                max_len = float('inf')

            strings_text.configure(state="normal")
            strings_text.delete("1.0", "end")

            # Apply length filter
            length_filtered = [s for s in extraction_data["strings"] if min_len <= len(s) <= max_len]

            if not search_term:
                if length_filtered:
                    display_text = "\n".join(length_filtered[:5000])  # Limit for performance
                    strings_text.insert("1.0", display_text)
                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (filtered by length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
                    status_label.configure(text=f"Showing: {len(length_filtered)} strings{filter_msg}")
                else:
                    strings_text.insert("1.0", "No strings match the filters")
                    status_label.configure(text="No matches")
            else:
                # Filter by search term
                filtered = [s for s in length_filtered if search_term in s.lower()]

                if filtered:
                    for s in filtered[:5000]:
                        strings_text.insert("end", s + "\n")
                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
                    status_label.configure(text=f"Found: {len(filtered)} matches{filter_msg}")
                else:
                    strings_text.insert("1.0", f"No strings found matching '{search_term}'")
                    status_label.configure(text="No matches")

            strings_text.configure(state="disabled")

        search_entry.bind("<KeyRelease>", search_strings)
        min_length_entry.bind("<KeyRelease>", search_strings)
        max_length_entry.bind("<KeyRelease>", search_strings)

        def extract_file_strings():
            """Extract strings from file in background"""
            try:
                status_label.configure(text="Extracting strings from file...")
                export_btn.configure(state="disabled")

                # Import file string extractor
                import sys
                import os
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analysis_modules'))
                from file_string_extractor import FileStringExtractor

                extractor = FileStringExtractor(verbose=True)

                # Get settings
                use_quality_filter = quality_filter_var.get()

                # Progress callback
                def progress_callback(bytes_processed, total_bytes, current_strings):
                    pct = (bytes_processed / total_bytes * 100) if total_bytes > 0 else 0
                    self.root.after(0, lambda: status_label.configure(
                        text=f"Extracting: {pct:.0f}% ({current_strings} strings so far...)"
                    ))

                # Extract strings
                result = extractor.extract_strings_from_file(
                    file_path,
                    min_length=4,
                    max_strings=50000,
                    include_unicode=True,
                    enable_quality_filter=use_quality_filter,
                    progress_callback=progress_callback,
                    scan_mode="quick"
                )

                # Combine all strings
                all_strings = []
                for category, strings in result['strings'].items():
                    all_strings.extend(strings)

                extraction_data["strings"] = all_strings
                extraction_data["extraction_result"] = result

                # Update UI
                self.root.after(0, lambda: status_label.configure(
                    text=f"Complete: {len(all_strings)} strings extracted in {result.get('extraction_time', 0):.2f}s"
                ))
                self.root.after(0, lambda: export_btn.configure(state="normal"))
                self.root.after(0, search_strings)

            except Exception as e:
                import traceback
                traceback.print_exc()
                self.root.after(0, lambda: status_label.configure(text=f"Error: {str(e)}"))
                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", f"Error extracting strings:\n{str(e)}"))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: export_btn.configure(state="normal"))

        def export_file_strings():
            """Export strings to TXT file"""
            try:
                if not extraction_data["extraction_result"]:
                    messagebox.showwarning("No Data", "No strings available to export")
                    return

                from tkinter import filedialog
                default_name = f"{os.path.splitext(file_name)[0]}_strings.txt"
                save_path = filedialog.asksaveasfilename(
                    title="Export Strings",
                    defaultextension=".txt",
                    initialfile=default_name,
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )

                if not save_path:
                    return

                # Import file string extractor
                import sys
                import os
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analysis_modules'))
                from file_string_extractor import FileStringExtractor

                extractor = FileStringExtractor()
                success = extractor.export_to_txt(
                    extraction_data["extraction_result"],
                    save_path,
                    include_metadata=True
                )

                if success:
                    messagebox.showinfo("Export Complete", f"Strings exported to:\n{save_path}")
                else:
                    messagebox.showerror("Export Failed", "Failed to export strings")

            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting:\n{str(e)}")
                import traceback
                traceback.print_exc()

        # Set button commands
        export_btn.configure(command=export_file_strings)
        quality_filter_checkbox.configure(command=lambda: threading.Thread(target=extract_file_strings, daemon=True).start())

        # Start initial extraction
        import threading
        threading.Thread(target=extract_file_strings, daemon=True).start()

    def open_folder_location(self):
        """Open the folder containing the selected process's executable"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to view")
            return

        item = self.process_tree.item(selection[0])
        file_path = item['values'][2]  # File Path column

        if not file_path or file_path == "N/A":
            messagebox.showerror("Error", "Process does not have an accessible file path")
            return

        try:
            # Get the directory containing the file
            folder_path = os.path.dirname(file_path)

            # Check if path exists
            if not os.path.exists(folder_path):
                messagebox.showerror("Error", f"Folder does not exist: {folder_path}")
                return

            # Open folder based on platform
            system = platform.system()
            if system == "Windows":
                # On Windows, use explorer with /select to highlight the file
                subprocess.run(['explorer', '/select,', file_path])
            elif system == "Darwin":  # macOS
                # On macOS, use open with -R to reveal in Finder
                subprocess.run(['open', '-R', file_path])
            else:  # Linux and other Unix-like systems
                # On Linux, open the folder (xdg-open doesn't support file selection)
                subprocess.run(['xdg-open', folder_path])

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder location: {str(e)}")

    def kill_selected_process(self):
        """Kill selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to kill")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['values'][1]

        if messagebox.askyesno("Confirm Kill",
                              f"Are you sure you want to kill process {name} (PID {pid})?"):
            success = self.process_monitor.kill_process(pid)
            if success:
                messagebox.showinfo("Success", f"Process {pid} terminated")
                self.refresh_process_list()
            else:
                messagebox.showerror("Error", f"Failed to kill process {pid}")

    def suspend_selected_process(self):
        """Suspend/pause selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to suspend")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['values'][1]

        success = self.process_monitor.suspend_process(pid)
        if success:
            self.refresh_process_list()
        else:
            messagebox.showerror("Error", f"Failed to suspend process {pid}")

    def resume_selected_process(self):
        """Resume suspended process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to resume")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['values'][1]

        success = self.process_monitor.resume_process(pid)
        if success:
            messagebox.showinfo("Success", f"Process {pid} resumed")
            self.refresh_process_list()
        else:
            messagebox.showerror("Error", f"Failed to resume process {pid}")

    # FIXED: Added proper null checks for callback
    def on_new_process_detected(self, proc_info):
        """Callback when new process is detected"""
        # Check if proc_info is valid
        if not proc_info:
            return

        # Always refresh process list when a new process is detected
        self.root.after(0, self.refresh_process_list)

        if proc_info.get('threat_detected'):
            # Get scan results
            scan_results = proc_info.get('scan_results', {})
            if not scan_results:
                return

            rule = scan_results.get('rule', 'Unknown')
            threat_score = scan_results.get('threat_score', 0)
            risk_level = scan_results.get('risk_level', 'Unknown')
            strings = scan_results.get('strings', [])

            # Increment total YARA match count
            self.total_yara_matches += 1

            # Update the badge display
            self.root.after(0, self.update_yara_match_badge)

            # Check if we should show popup (limits to 3 per rule family)
            if not self.should_show_popup(rule):
                # Popup suppressed, but match still counted and visible in filter
                return

            # Show alert in GUI thread
            def show_alert():
                alert = ctk.CTkToplevel(self.root)
                alert.title("⚠️ Threat Detected")
                alert.geometry("700x650")
                alert.minsize(600, 500)
                alert.attributes('-topmost', True)

                # Main container frame
                main_frame = ctk.CTkFrame(alert, fg_color=self.colors["red_dark"])
                main_frame.pack(fill="both", expand=True, padx=2, pady=2)

                # Header section
                header_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                header_frame.pack(fill="x", padx=10, pady=(15, 10))

                title = ctk.CTkLabel(
                    header_frame,
                    text="⚠️ MALICIOUS PROCESS DETECTED",
                    font=Fonts.title_large,
                    text_color="white"
                )
                title.pack()

                # Content section (scrollable)
                content_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                content_frame.pack(fill="both", expand=True, padx=10, pady=5)

                # Get all matched rules
                all_rules = scan_results.get('all_rules', [rule])
                rules_display = ', '.join(all_rules) if len(all_rules) > 1 else rule

                # Details section
                details_frame = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                details_frame.pack(fill="x", padx=10, pady=10)

                details = f"""PID: {proc_info['pid']}
Name: {proc_info['name']}
Path: {proc_info['exe']}

YARA Rule(s): {rules_display}
Threat Score: {threat_score}
Risk Level: {risk_level}"""

                details_label = ctk.CTkLabel(
                    details_frame,
                    text=details,
                    font=Fonts.body,
                    justify="left",
                    text_color="white"
                )
                details_label.pack(pady=15, padx=15, anchor="w")

                # Matched strings section
                if strings:
                    strings_header = ctk.CTkLabel(
                        content_frame,
                        text=f"Matched Strings ({len(strings)}):",
                        font=Fonts.body_bold,
                        text_color="white"
                    )
                    strings_header.pack(pady=(5, 5), padx=10, anchor="w")

                    # Scrollable strings container with fixed height
                    strings_container = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                    strings_container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

                    strings_frame = ctk.CTkScrollableFrame(
                        strings_container,
                        fg_color="#2b2b2b",
                        height=250
                    )
                    strings_frame.pack(fill="both", expand=True, padx=5, pady=5)

                    # Display all strings
                    for i, s in enumerate(strings, 1):
                        s_display = s[:100] + "..." if len(s) > 100 else s
                        string_label = ctk.CTkLabel(
                            strings_frame,
                            text=f"{i}. {s_display}",
                            font=Fonts.helper,
                            text_color="white",
                            anchor="w",
                            justify="left"
                        )
                        string_label.pack(anchor="w", pady=2, padx=5, fill="x")

                # Footer with close button (always visible)
                footer_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                footer_frame.pack(fill="x", padx=10, pady=(5, 15))

                btn_close = ctk.CTkButton(
                    footer_frame,
                    text="Close",
                    command=alert.destroy,
                    fg_color=self.colors["navy"],
                    hover_color=self.colors["dark_blue"],
                    width=120,
                    height=35
                )
                btn_close.pack(pady=5)

            self.root.after(0, show_alert)
    
    # FIXED: Added network callback stub
    def on_new_connection_detected(self, conn_info):
        """Callback when new network connection is detected"""
        if not conn_info:
            return
        
        if conn_info.get('suspicious'):
            # Could add network alerts here
            pass
    
    # ==================== NETWORK MONITOR METHODS ====================
    def toggle_network_monitoring(self):
        """Toggle network monitoring on/off"""
        if not self.network_monitor_active:
            self.network_monitor.start_monitoring()
            self.network_monitor_active = True
            self.btn_toggle_network_monitor.configure(text="⏸ Stop Monitoring")
        else:
            self.network_monitor.stop_monitoring()
            self.network_monitor_active = False
            self.btn_toggle_network_monitor.configure(text="▶ Start Monitoring")
    
    def show_network_context_menu(self, event):
        """Show right-click context menu for network connections"""
        try:
            self.network_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.network_context_menu.grab_release()

    def copy_network_cell(self, column_index):
        """Copy a specific cell from selected network row to clipboard"""
        selection = self.network_tree.selection()
        if not selection:
            return

        try:
            item = self.network_tree.item(selection[0])
            values = item['values']
            if values and len(values) > column_index:
                cell_value = str(values[column_index])
                self.root.clipboard_clear()
                self.root.clipboard_append(cell_value)
                self.root.update()  # Keep clipboard after window closes
        except Exception as e:
            pass

    def copy_network_row(self):
        """Copy entire row from selected network connection to clipboard"""
        selection = self.network_tree.selection()
        if not selection:
            return

        try:
            item = self.network_tree.item(selection[0])
            values = item['values']
            if values:
                # Format: Type | Local | Remote | Hostname | Status | Process | Suspicious
                row_text = " | ".join(str(v) for v in values)
                self.root.clipboard_clear()
                self.root.clipboard_append(row_text)
                self.root.update()  # Keep clipboard after window closes
        except Exception as e:
            pass

    def add_network_ioc_to_case(self, field_type):
        """Add selected network IOC to current case"""
        if not self.current_case:
            messagebox.showwarning("No Active Case", "No active case to add IOC to. Please create or load a case first.")
            return

        selection = self.network_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a network connection first.")
            return

        try:
            item = self.network_tree.item(selection[0])
            values = item['values']  # [Type, Local, Remote, Hostname, Status, Process, Suspicious]

            if field_type == "remote_ip" and len(values) > 2:
                # Extract IP from "IP:Port" format in Remote column (index 2)
                remote_addr = str(values[2])
                remote_ip = remote_addr.split(':')[0] if ':' in remote_addr else remote_addr

                # Validate it's not empty or just a dash
                if remote_ip and remote_ip != '-':
                    self.case_manager.add_ioc("ips", remote_ip)
                    self.refresh_iocs_display()
                    messagebox.showinfo("Success", f"Added IP '{remote_ip}' to case IOCs!")
                else:
                    messagebox.showwarning("Invalid IP", "No valid IP address found in the selected connection.")

            elif field_type == "hostname" and len(values) > 3:
                hostname = str(values[3])
                # Validate hostname is not empty or dash
                if hostname and hostname != '-':
                    self.case_manager.add_ioc("domains", hostname)
                    self.refresh_iocs_display()
                    messagebox.showinfo("Success", f"Added domain '{hostname}' to case IOCs!")
                else:
                    messagebox.showwarning("Invalid Hostname", "No valid hostname found in the selected connection.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to add IOC: {str(e)}")

    def add_live_event_iocs_to_case(self, events_tree):
        """Extract and add IOCs from selected live event(s) to current case"""
        if not self.current_case:
            messagebox.showwarning("No Active Case", "No active case to add IOCs to. Please create or load a case first.")
            return

        selections = events_tree.selection()
        if not selections:
            messagebox.showwarning("No Selection", "Please select one or more live events first.")
            return

        try:
            # Collect all text from selected events to extract IOCs
            all_text = []
            for selection in selections:
                item = events_tree.item(selection)
                values = item['values']  # [time, pid, process, type, operation, path, result]

                # Get path/target field (index 5) which is most likely to contain IOCs
                if len(values) > 5:
                    path = str(values[5])
                    all_text.append(path)

            # Join all text and extract IOCs using case_manager's built-in method
            combined_text = " ".join(all_text)
            extracted_iocs = self.case_manager.extract_iocs_from_text(combined_text)

            # Add extracted IOCs to case
            total_added = 0
            for ioc_type in ['urls', 'ips', 'domains']:
                if extracted_iocs.get(ioc_type):
                    for ioc_value in extracted_iocs[ioc_type]:
                        self.case_manager.add_ioc(ioc_type, ioc_value)
                        total_added += 1

            if total_added > 0:
                self.refresh_iocs_display()
                ioc_summary = f"URLs: {len(extracted_iocs.get('urls', []))}, IPs: {len(extracted_iocs.get('ips', []))}, Domains: {len(extracted_iocs.get('domains', []))}"
                messagebox.showinfo("Success", f"Extracted and added {total_added} IOC(s) to case!\n\n{ioc_summary}")
            else:
                messagebox.showinfo("No IOCs Found", "No IOCs (URLs, IPs, or domains) were found in the selected event(s).")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract IOCs: {str(e)}")

    def resolve_hostname(self, ip_address):
        """Resolve IP address to hostname with caching"""
        # Initialize hostname cache if not exists
        if not hasattr(self, 'hostname_cache'):
            self.hostname_cache = {}

        # Check cache first
        if ip_address in self.hostname_cache:
            return self.hostname_cache[ip_address]

        # Skip resolution for local/private IPs
        if ip_address in ['', '0.0.0.0', '127.0.0.1', 'localhost', '*']:
            self.hostname_cache[ip_address] = '-'
            return '-'

        # Try to resolve
        try:
            import socket
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.hostname_cache[ip_address] = hostname
            return hostname
        except:
            # If resolution fails, just use the IP
            self.hostname_cache[ip_address] = '-'
            return '-'

    def refresh_network_list(self):
        """Refresh network connections list"""
        # Clear existing
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)

        # Get connections
        connections = self.network_monitor.get_all_connections()

        for conn in connections:
            local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
            remote_addr = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"

            # Resolve hostname for remote IP
            remote_ip = conn.get('remote_ip', '')
            hostname = self.resolve_hostname(remote_ip) if remote_ip else '-'

            suspicious_text = "Yes" if conn.get('suspicious', False) else "No"
            tags = ('suspicious',) if conn.get('suspicious', False) else ()

            self.network_tree.insert(
                "", "end",
                values=(
                    conn.get('type', ''),
                    local_addr,
                    remote_addr,
                    hostname,
                    conn.get('status', ''),
                    conn.get('process_name', 'Unknown'),
                    suspicious_text
                ),
                tags=tags
            )
        
        # Update stats
        if self.network_monitor_active:
            summary = self.network_monitor.get_connection_summary()
            stats_text = f"""Network Statistics:
Active: {summary['active_connections']} | Total: {summary['total_connections']} | Suspicious: {summary['suspicious_connections']}
Unique IPs: {summary['unique_remote_ips']} | Unique Ports: {summary['unique_local_ports']}"""
            self.network_stats_label.configure(text=stats_text)

    # ==================== FILE VIEWER AND EXECUTOR ====================
    def view_file_hex(self, file_path, file_name):
        """View file in hex format"""
        viewer = get_viewer_executor()

        # Create window
        hex_window = ctk.CTkToplevel(self.root)
        hex_window.title(f"Hex View: {file_name}")
        hex_window.geometry("1200x700")

        # Main container
        main_container = ctk.CTkFrame(hex_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(
            header,
            text=f"🔍 Hex View: {file_name}",
            font=Fonts.logo_subtitle
        )
        title.pack(side="left", padx=20, pady=15)

        # File info
        file_info = viewer.get_file_info(file_path)
        info_text = f"Size: {file_info.get('size_kb', 0):.2f} KB"
        info_label = ctk.CTkLabel(
            header,
            text=info_text,
            font=Fonts.helper,
            text_color="gray60"
        )
        info_label.pack(side="right", padx=20)

        # Text display with scrollbar
        text_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create text widget
        hex_text = tk.Text(
            text_frame,
            wrap="none",
            bg="#0d1520",
            fg="#ffffff",
            font=("Courier New", 10),
            selectbackground="#2a4d6e",
            selectforeground="#ffffff"
        )

        # Scrollbars
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=hex_text.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=hex_text.xview)
        hex_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Pack scrollbars and text
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        hex_text.pack(side="left", fill="both", expand=True)

        # Load hex content in background
        def load_hex():
            hex_content, bytes_read = viewer.read_file_as_hex(file_path, max_bytes=1024*1024)  # 1MB max
            hex_text.delete("1.0", "end")
            hex_text.insert("1.0", hex_content)
            hex_text.configure(state="disabled")  # Make read-only

            if bytes_read >= 1024*1024:
                hex_text.insert("end", f"\n\n... (showing first 1MB of {file_info.get('size_mb', 0):.2f} MB)")

        # Load in thread to avoid freezing GUI
        threading.Thread(target=load_hex, daemon=True).start()

    def view_file_text(self, file_path, file_name):
        """View file as text"""
        viewer = get_viewer_executor()

        # Create window
        text_window = ctk.CTkToplevel(self.root)
        text_window.title(f"Text View: {file_name}")
        text_window.geometry("1200x700")

        # Main container
        main_container = ctk.CTkFrame(text_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(
            header,
            text=f"📄 Text View: {file_name}",
            font=Fonts.logo_subtitle
        )
        title.pack(side="left", padx=20, pady=15)

        # File info
        file_info = viewer.get_file_info(file_path)
        info_text = f"Size: {file_info.get('size_kb', 0):.2f} KB"
        info_label = ctk.CTkLabel(
            header,
            text=info_text,
            font=Fonts.helper,
            text_color="gray60"
        )
        info_label.pack(side="right", padx=20)

        # Text display with scrollbar
        text_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create text widget with line numbers
        line_frame = tk.Frame(text_frame, bg="#0d1520")
        line_frame.pack(side="left", fill="y")

        line_numbers = tk.Text(
            line_frame,
            width=6,
            wrap="none",
            bg="#1a2332",
            fg="gray60",
            font=("Courier New", 10),
            state="disabled",
            takefocus=0
        )
        line_numbers.pack(side="left", fill="y")

        text_widget = tk.Text(
            text_frame,
            wrap="none",
            bg="#0d1520",
            fg="#ffffff",
            font=("Courier New", 10),
            selectbackground="#2a4d6e",
            selectforeground="#ffffff"
        )

        # Scrollbars
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=text_widget.xview)
        text_widget.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Pack scrollbars and text
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        text_widget.pack(side="left", fill="both", expand=True)

        # Load text content in background
        def load_text():
            text_content, lines_read = viewer.read_file_as_text(file_path, max_lines=10000)
            text_widget.delete("1.0", "end")
            text_widget.insert("1.0", text_content)

            # Add line numbers
            line_numbers.configure(state="normal")
            line_numbers.delete("1.0", "end")
            for i in range(1, min(lines_read + 1, 10001)):
                line_numbers.insert("end", f"{i:5d}\n")
            line_numbers.configure(state="disabled")

            text_widget.configure(state="disabled")  # Make read-only

        # Load in thread
        threading.Thread(target=load_text, daemon=True).start()

    def execute_file(self, file_path, file_name, suspended=False):
        """Execute file and redirect to Analysis tab"""
        viewer = get_viewer_executor()

        # Check if can execute
        if not viewer.can_execute(file_path):
            messagebox.showwarning(
                "Cannot Execute",
                f"No execution handler for this file type.\n\nSupported: .py, .ps1, .bat, .cmd, .exe, .dll, .msi, .js, .vbs, .wsf, .hta"
            )
            return

        # Confirmation dialog
        mode_text = "in SUSPENDED state" if suspended else ""
        result = messagebox.askyesno(
            "Execute File",
            f"Are you sure you want to execute {mode_text}:\n\n{file_name}\n\nThis file will run on your system!",
            icon='warning'
        )

        if not result:
            return

        # Execute the file
        exec_result = viewer.execute_file(file_path, suspended=suspended)

        if not exec_result.get('success'):
            messagebox.showerror("Execution Error", exec_result.get('error', 'Unknown error'))
            return

        # Get PID for focusing
        pid = exec_result.get('pid', None)

        # Show success message with PID if available
        if suspended:
            messagebox.showinfo(
                "Process Created",
                f"Process created in SUSPENDED state!\n\nPID: {pid}\nFile: {file_name}\n\nSwitching to Analysis tab..."
            )
        else:
            if pid:
                messagebox.showinfo(
                    "Process Launched",
                    f"Process launched successfully!\n\nPID: {pid}\nFile: {file_name}\n\nSwitching to Analysis tab..."
                )

        # Switch to Analysis tab
        self.show_tab("analysis")

        # Focus on the executed process (with slight delay to allow tree to refresh)
        if pid:
            self.root.after(500, lambda: self.focus_process_by_pid(pid))


# Main entry point
if __name__ == "__main__":
    app = ForensicAnalysisGUI()
    app.run()
