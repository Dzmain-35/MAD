
import customtkinter as ctk
from tkinter import filedialog, messagebox
from datetime import datetime
from case_manager import CaseManager
from PIL import Image
import os
import threading
from analysis_modules.process_monitor import ProcessMonitor
from analysis_modules.network_monitor import NetworkMonitor
from analysis_modules.procmon_events import ProcmonLiveMonitor, ProcmonEvent
import tkinter as tk
from tkinter import ttk

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
        
        # Initialize case manager (will auto-detect paths)
        self.case_manager = CaseManager()
        print(f"Case storage initialized at: {self.case_manager.case_storage_path}")
        
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
        
        # Monitoring states
        self.process_monitor_active = False
        self.network_monitor_active = False

        # Procmon live monitors (PID -> monitor instance)
        self.procmon_monitors = {}
        
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
                            font=ctk.CTkFont(size=20, weight="bold"),
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
            height=45, font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            corner_radius=8
        )
        self.btn_new_case.pack(fill="x", pady=5)
        
        self.btn_current_case = ctk.CTkButton(
            nav_frame, text="Current Case",
            command=lambda: self.show_tab("current_case"),
            height=45, font=ctk.CTkFont(size=14, weight="bold"),
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
            height=45, font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            corner_radius=8
        )
        self.btn_analysis.pack(fill="x", pady=5)
        
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
            font=ctk.CTkFont(size=36, weight="bold"),
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
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="white",
            anchor="w"
        )
        analyst_label.pack(anchor="w", padx=5, pady=(0, 5))
        
        self.analyst_name_entry = ctk.CTkEntry(
            form_container,
            width=400,
            height=40,
            placeholder_text="Enter your name",
            font=ctk.CTkFont(size=14),
            fg_color=self.colors["navy"],
            border_color=self.colors["red"],
            border_width=2
        )
        self.analyst_name_entry.pack(padx=5, pady=(0, 15))
        
        # Report URL input
        report_label = ctk.CTkLabel(
            form_container,
            text="Report URL",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="white",
            anchor="w"
        )
        report_label.pack(anchor="w", padx=5, pady=(0, 5))
        
        self.report_url_entry = ctk.CTkEntry(
            form_container,
            width=400,
            height=40,
            placeholder_text="Enter report URL",
            font=ctk.CTkFont(size=14),
            fg_color=self.colors["navy"],
            border_color=self.colors["red"],
            border_width=2
        )
        self.report_url_entry.pack(padx=5, pady=(0, 20))
        
        # Upload button
        btn_upload = ctk.CTkButton(
            center_container,
            text="Upload File to Start Case",
            command=self.handle_new_case_upload,
            height=50,
            width=400,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            corner_radius=8
        )
        btn_upload.pack(pady=(0, 10))
        
        # Status label for feedback
        self.new_case_status = ctk.CTkLabel(
            center_container,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="white"
        )
        self.new_case_status.pack(pady=10)
        
        self.tabs["new_case"] = frame
    
    def create_fallback_logo(self, parent_frame):
        """Create fallback text-based logo if image.png is not found"""
        logo_shield = ctk.CTkLabel(
            parent_frame,
            text="🛡",
            font=ctk.CTkFont(size=80),
            text_color=self.colors["red"]
        )
        logo_shield.pack(side="left", padx=(0, 20))
        
        logo_text_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        logo_text_frame.pack(side="left")
        
        logo_main = ctk.CTkLabel(
            logo_text_frame,
            text="M.A.D.",
            font=ctk.CTkFont(size=72, weight="bold"),
            text_color="white"
        )
        logo_main.pack(anchor="w")
        
        logo_subtitle = ctk.CTkLabel(
            logo_text_frame,
            text="MALWARE ANALYSIS\nDASHBOARD",
            font=ctk.CTkFont(size=20, weight="bold"),
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
                            font=ctk.CTkFont(size=24, weight="bold"),
                            text_color="white")
        title.pack(side="left")
        
        self.case_status_label = ctk.CTkLabel(header_frame, text="",
                                             corner_radius=20,
                                             fg_color="#2D7A3E",
                                             width=100, height=30,
                                             text_color="white",
                                             font=ctk.CTkFont(size=11, weight="bold"))
        self.case_status_label.pack(side="right", padx=10)
        
        # Scrollable frame for content
        scroll_frame = ctk.CTkScrollableFrame(frame, corner_radius=10, fg_color=self.colors["navy"])
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        
        # Case details card - COMPACT VERSION
        self.case_details_frame = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20")
        self.case_details_frame.pack(fill="x", pady=5)
        
        details_title = ctk.CTkLabel(self.case_details_frame, text="Case Details",
                                    font=ctk.CTkFont(size=16, weight="bold"),
                                    text_color="white")
        details_title.pack(pady=10, padx=15, anchor="w")
        
        self.case_info_frame = ctk.CTkFrame(self.case_details_frame, 
                                           fg_color="transparent")
        self.case_info_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        # Files section header
        files_header = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="transparent")
        files_header.pack(fill="x", pady=(10, 5))
        
        files_title = ctk.CTkLabel(files_header, text="Uploaded Files",
                                  font=ctk.CTkFont(size=16, weight="bold"),
                                  text_color="white")
        files_title.pack(side="left", padx=15)
        
        btn_add_files = ctk.CTkButton(files_header, text="➕ Add Files",
                                     command=self.handle_add_files,
                                     height=30, width=100,
                                     fg_color=self.colors["red"],
                                     hover_color=self.colors["red_dark"],
                                     font=ctk.CTkFont(size=11, weight="bold"))
        btn_add_files.pack(side="right", padx=15)
        
        # Files list container
        self.files_list_frame = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="transparent")
        self.files_list_frame.pack(fill="x", pady=(0, 10))
        
        # Notes section
        notes_header = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="transparent")
        notes_header.pack(fill="x", pady=(10, 5))
        
        notes_title = ctk.CTkLabel(notes_header, text="Case Notes",
                                  font=ctk.CTkFont(size=16, weight="bold"),
                                  text_color="white")
        notes_title.pack(side="left", padx=15)
        
        # Save notes button
        btn_save_notes = ctk.CTkButton(notes_header, text="💾 Save Notes",
                                      command=self.handle_save_notes,
                                      height=30, width=100,
                                      fg_color=self.colors["red"],
                                      hover_color=self.colors["red_dark"],
                                      font=ctk.CTkFont(size=11, weight="bold"))
        btn_save_notes.pack(side="right", padx=15)
        
        # Notes text area
        notes_container = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20")
        notes_container.pack(fill="both", expand=True, pady=(0, 10))
        
        self.notes_textbox = tk.Text(
            notes_container,
            wrap="word",
            bg="#1a1a1a",
            fg="#ffffff",
            font=("Segoe UI", 11),
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
                            font=ctk.CTkFont(size=28, weight="bold"),
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
            font=ctk.CTkFont(size=12, weight="bold")
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
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.btn_network.pack(side="left", padx=5)
        
        # Content area for sub-tabs
        self.analysis_content = ctk.CTkFrame(frame, corner_radius=10, fg_color=self.colors["navy"])
        self.analysis_content.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Create sub-tab frames
        self.analysis_subtabs = {}
        self.create_processes_subtab()
        self.create_network_subtab()
        
        self.tabs["analysis"] = frame
        self.show_analysis_subtab("processes")
        
    def create_processes_subtab(self):
        """Create Processes sub-tab with optimized tree view"""
        frame = ctk.CTkFrame(self.analysis_content, fg_color="transparent")
        
        # Header with controls
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)
        
        title = ctk.CTkLabel(header, text="Process Analysis",
                            font=ctk.CTkFont(size=18, weight="bold"),
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
        
        # Refresh button
        btn_refresh = ctk.CTkButton(
            header, text="🔄 Refresh",
            command=self.refresh_process_list,
            height=35, width=100,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"]
        )
        btn_refresh.pack(side="right", padx=5)
        
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
        self.process_context_menu.add_separator(background="#444444")
        self.process_context_menu.add_command(
            label="❌ Kill Process", 
            command=self.kill_selected_process
        )
        
        self.process_tree.bind("<Button-3>", self.show_process_context_menu)
        self.process_tree.bind("<Double-1>", lambda e: self.view_process_details_and_strings())  # FIXED
        
        # Configure tag colors
        self.process_tree.tag_configure('threat', background='#5c1c1c', foreground='white')
        self.process_tree.tag_configure('system', foreground='#888888')
        
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
                            font=ctk.CTkFont(size=18, weight="bold"),
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
            font=ctk.CTkFont(size=11),
            justify="left"
        )
        self.network_stats_label.pack(padx=15, pady=10, anchor="w")
        
        # Connection list
        tree_frame = ctk.CTkFrame(frame, fg_color="gray20")
        tree_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        vsb = tk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side="right", fill="y")
        
        columns = ("Type", "Local", "Remote", "Status", "Process", "Suspicious")
        self.network_tree = ttk.Treeview(tree_frame, columns=columns, 
                                        show="headings", yscrollcommand=vsb.set)
        self.network_tree.pack(side="left", fill="both", expand=True)
        vsb.config(command=self.network_tree.yview)
        
        # Configure columns
        for col in columns:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=100)
        
        # Configure tag colors
        self.network_tree.tag_configure('suspicious', background='#5c1c1c')
        
        self.analysis_subtabs["network"] = frame
        
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
    
    # ==================== EVENT HANDLERS ====================
    def handle_new_case_upload(self):
        """Handle file upload for new case - delegates to case_manager"""
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
            
            # Initialize case data
            case_data = {
                "id": case_id,
                "created": datetime.now().isoformat(),
                "status": "ACTIVE",
                "analyst_name": analyst_name,
                "report_url": report_url,
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
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(0, 5))
        
        subtitle = ctk.CTkLabel(
            container,
            text="YARA & Threat Intelligence Analysis",
            font=ctk.CTkFont(size=12),
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
            font=ctk.CTkFont(size=13, weight="bold")
        )
        self.progress_label.pack(pady=10)
        
        # Current file label
        self.current_file_label = ctk.CTkLabel(
            container,
            text="Initializing...",
            font=ctk.CTkFont(size=11),
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
        """Handle adding files to existing case - delegates to case_manager"""
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
        
        try:
            # Add files using case_manager
            case_data = self.case_manager.add_files_to_case(list(files))
            self.current_case = case_data
            
            self.update_current_case_display()
            messagebox.showinfo(
                "Success", 
                f"Added {len(files)} files to case\n"
                f"Total files: {len(case_data['files'])}\n"
                f"Total threats: {case_data['total_threats']}"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add files: {str(e)}")
        
        finally:
            self.scan_in_progress = False
    
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
                              text_color="gray60", font=ctk.CTkFont(size=11))
            lbl.pack(anchor="w")
            
            val = ctk.CTkLabel(detail_frame, text=value,
                              font=ctk.CTkFont(size=12, weight="bold"),
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
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="white",
            cursor="hand2"
        )
        name_label.pack(anchor="w")
        
        # YARA and THQ matches display in one line
        yara_display = self.case_manager.get_yara_display_text(yara_matches)
        thq_display = thq_family if thq_family and thq_family != "Unknown" else "N/A"
        
        info_line = f"YARA: {yara_display}  |  THQ: {thq_display}"
        
        yara_thq_label = ctk.CTkLabel(
            left_frame, 
            text=info_line,
            text_color=self.colors["red"] if (yara_matches or thq_family != "Unknown") else "gray60", 
            font=ctk.CTkFont(size=12, weight="bold"),
            cursor="hand2"
        )
        yara_thq_label.pack(anchor="w", pady=(3, 0))
        
        # File size and timestamp
        size_kb = file_info.get("file_size", 0) / 1024
        info_text = f"{size_kb:.2f} KB | {datetime.fromisoformat(file_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}"
        info_label = ctk.CTkLabel(
            left_frame, text=info_text,
            text_color="gray60", font=ctk.CTkFont(size=10),
            cursor="hand2"
        )
        info_label.pack(anchor="w", pady=(2, 0))
        
        # Right side - copy button and expand indicator
        right_frame = ctk.CTkFrame(header_frame, fg_color="transparent", cursor="hand2")
        right_frame.grid(row=0, column=1, sticky="e", padx=(10, 0))
        
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
            right_frame,
            text="📋 Copy Details",
            width=120,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            cursor="hand2"
        )
        copy_btn.pack(side="top", pady=(0, 5))
        copy_btn.bind("<Button-1>", copy_details)
        
        # Expand/Collapse indicator
        details_visible = [False]
        details_frame = ctk.CTkFrame(card_frame, fg_color="#0d1520", height=200)
        
        expand_indicator = ctk.CTkLabel(
            right_frame,
            text="▼",
            font=ctk.CTkFont(size=14),
            text_color="gray60",
            cursor="hand2"
        )
        expand_indicator.pack(side="top")
        
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
            font=("Courier", 10),
            height=12,
            relief="flat",
            padx=10,
            pady=10
        )
        text_widget.insert("1.0", details_text)
        text_widget.configure(state="disabled")  # Make read-only
        text_widget.pack(fill="both", expand=True)
    
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

        self.root.mainloop()

    # ==================== PROCESS MONITOR METHODS ====================
    def toggle_process_monitoring(self):
        """Toggle process monitoring on/off"""
        if not self.process_monitor_active:
            self.process_monitor.start_monitoring()
            self.process_monitor_active = True
            self.btn_toggle_process_monitor.configure(text="⏸ Stop Monitoring")
            messagebox.showinfo("Monitoring Active", 
                              "Process monitoring started. New processes will be automatically scanned with YARA.")
        else:
            self.process_monitor.stop_monitoring()
            self.process_monitor_active = False
            self.btn_toggle_process_monitor.configure(text="▶ Start Monitoring")
    
    def refresh_process_list(self):
        """Refresh the process tree with parent-child hierarchy, preserving expanded state"""
        # Save currently expanded items and their PIDs
        expanded_pids = set()
        
        def get_expanded_pids(item=""):
            children = self.process_tree.get_children(item)
            for child in children:
                if self.process_tree.item(child, 'open'):
                    # Get PID from values
                    values = self.process_tree.item(child, 'values')
                    if values and len(values) > 0:
                        try:
                            expanded_pids.add(int(values[0]))
                        except:
                            pass
                get_expanded_pids(child)
        
        get_expanded_pids()
        
        # Save currently selected item PID
        selected_pid = None
        selection = self.process_tree.selection()
        if selection:
            try:
                values = self.process_tree.item(selection[0], 'values')
                if values and len(values) > 0:
                    selected_pid = int(values[0])
            except:
                pass
        
        # Clear existing
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Get all processes
        processes = self.process_monitor.get_all_processes()
        
        # Build process map by PID
        process_map = {}
        for proc in processes:
            process_map[proc['pid']] = proc
        
        # Build parent-child relationships
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
        
        # Store item IDs by PID for re-selection
        pid_to_item = {}
        
        # Recursive function to add process and children
        def add_process_tree(proc, parent_id=""):
            pid = proc['pid']
            name = proc['name']
            exe = proc.get('exe', 'N/A')
            
            # FIXED: Determine YARA match status with rule name
            yara_status = "No"
            tags = ()
            if proc.get('threat_detected'):
                # Get the actual rule name
                yara_rule = proc.get('yara_rule', 'Unknown')
                if yara_rule and yara_rule != 'Unknown':
                    yara_status = f"⚠️ {yara_rule}"  # Show rule name!
                else:
                    matches = proc.get('yara_matches', 0)
                    yara_status = f"⚠️ {matches} matches" if matches else "⚠️ YES"
                tags = ('threat',)
            elif name.lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                tags = ('system',)
            
            # Insert into tree
            item_id = self.process_tree.insert(
                parent_id, 
                "end",
                text=f"  {name}",  # Tree column shows name with indent
                values=(pid, name, exe, yara_status),
                tags=tags,
                open=pid in expanded_pids  # Restore expanded state
            )
            
            # Store for re-selection
            pid_to_item[pid] = item_id
            
            # Add children recursively
            if pid in children_map:
                for child in children_map[pid]:
                    add_process_tree(child, item_id)
        
        # Add root processes and their trees
        for proc in sorted(root_processes, key=lambda p: p['pid']):
            add_process_tree(proc)
        
        # Restore selection
        if selected_pid and selected_pid in pid_to_item:
            self.process_tree.selection_set(pid_to_item[selected_pid])
            self.process_tree.see(pid_to_item[selected_pid])
    
    def show_process_context_menu(self, event):
        """Show right-click context menu for processes"""
        try:
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

                msg = f"PID {pid} Scan Complete\n\n"
                msg += f"Matches Found: {'Yes' if matches_found else 'No'}\n\n"

                if matches_found and rule != 'No_YARA_Hit':
                    msg += f"Rule: {rule}\n"
                    msg += f"Threat Score: {threat_score}\n"
                    msg += f"Risk Level: {risk_level}\n\n"

                    if strings:
                        msg += f"Matched Strings ({len(strings)}):\n"
                        for s in strings[:5]:  # Show first 5
                            msg += f"  - {s[:50]}...\n" if len(s) > 50 else f"  - {s}\n"
                else:
                    msg += "No threats detected."

                self.root.after(0, lambda: messagebox.showinfo("Scan Results", msg))
                self.root.after(0, self.refresh_process_list)

        threading.Thread(target=scan, daemon=True).start()
    
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
            font=ctk.CTkFont(size=20, weight="bold")
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
                details += f"Rule Matched: {scan_results.get('rule', 'Unknown')}\n"
                details += f"Threat Score: {scan_results.get('threat_score', 0)}\n"
                details += f"Risk Level: {scan_results.get('risk_level', 'Unknown')}\n"
                
                if scan_results.get('strings'):
                    details += f"\nMatched Strings:\n"
                    for s in scan_results['strings'][:10]:
                        details += f"  - {s}\n"
        
        info_text = tk.Text(
            info_frame,
            wrap="word",
            bg="#1a1a1a",
            fg="#ffffff",
            font=("Courier", 11),
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
            font=ctk.CTkFont(size=12, weight="bold")
        )
        search_label.pack(side="left", padx=(10, 5))

        search_entry = ctk.CTkEntry(
            search_row,
            width=300,
            height=35,
            placeholder_text="Enter search term...",
            font=ctk.CTkFont(size=12)
        )
        search_entry.pack(side="left", padx=5)

        # Status label
        status_label = ctk.CTkLabel(
            search_row,
            text="Extracting strings...",
            font=ctk.CTkFont(size=11),
            text_color="gray60"
        )
        status_label.pack(side="left", padx=20)

        # Second row: Length filter and refresh button
        filter_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=5, pady=(5, 5))

        # Length filter
        length_label = ctk.CTkLabel(
            filter_row,
            text="📏 Length:",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        length_label.pack(side="left", padx=(10, 5))

        min_label = ctk.CTkLabel(
            filter_row,
            text="Min:",
            font=ctk.CTkFont(size=11)
        )
        min_label.pack(side="left", padx=(5, 2))

        min_length_entry = ctk.CTkEntry(
            filter_row,
            width=60,
            height=30,
            placeholder_text="4",
            font=ctk.CTkFont(size=11)
        )
        min_length_entry.insert(0, "4")
        min_length_entry.pack(side="left", padx=2)

        max_label = ctk.CTkLabel(
            filter_row,
            text="Max:",
            font=ctk.CTkFont(size=11)
        )
        max_label.pack(side="left", padx=(10, 2))

        max_length_entry = ctk.CTkEntry(
            filter_row,
            width=60,
            height=30,
            placeholder_text="∞",
            font=ctk.CTkFont(size=11)
        )
        max_length_entry.pack(side="left", padx=2)

        # Refresh button
        refresh_btn = ctk.CTkButton(
            filter_row,
            text="🔄 Refresh Strings",
            command=lambda: None,  # Will be set later
            height=30,
            width=140,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=ctk.CTkFont(size=11, weight="bold")
        )
        refresh_btn.pack(side="left", padx=15)
        
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
            font=("Courier", 10),
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        strings_text.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        vsb.config(command=strings_text.yview)
        hsb.config(command=strings_text.xview)
        
        # Store original strings
        all_strings_data = {"strings": [], "original_text": ""}

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
        
        # Extract strings in background
        def extract():
            try:
                status_label.configure(text="Extracting strings...")
                refresh_btn.configure(state="disabled", text="🔄 Extracting...")

                # Get minimum length for extraction (use lower value for more strings)
                try:
                    extract_min_length = int(min_length_entry.get()) if min_length_entry.get() else 4
                    # Use a lower min_length for extraction to capture more strings
                    extract_min_length = max(4, min(extract_min_length, 10))
                except ValueError:
                    extract_min_length = 4

                # Extract with increased limit for live refresh
                strings = self.process_monitor.extract_strings_from_process(
                    pid,
                    min_length=extract_min_length,
                    limit=20000  # Increased limit for better live refresh
                )

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

                all_strings_data["strings"] = strings
                all_strings_data["original_text"] = result_text

                # Update UI in main thread
                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", result_text))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: status_label.configure(
                    text=f"Total: {len(strings)} strings extracted | Use filters to refine"
                ))
                self.root.after(0, lambda: refresh_btn.configure(state="normal", text="🔄 Refresh Strings"))

                # Auto-apply current filters after extraction
                self.root.after(100, search_strings)

            except Exception as e:
                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", f"Error: {str(e)}"))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: status_label.configure(text="Error extracting strings"))
                self.root.after(0, lambda: refresh_btn.configure(state="normal", text="🔄 Refresh Strings"))

        def refresh_strings():
            """Refresh strings by re-extracting from process memory"""
            threading.Thread(target=extract, daemon=True).start()

        # Set refresh button command
        refresh_btn.configure(command=refresh_strings)

        # Initial extraction
        threading.Thread(target=extract, daemon=True).start()

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
            font=ctk.CTkFont(size=11),
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
            font=ctk.CTkFont(size=12, weight="bold")
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

                # Auto-scroll to bottom
                if events_tree.get_children():
                    events_tree.see(events_tree.get_children()[-1])

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

            # Show alert in GUI thread
            def show_alert():
                alert = ctk.CTkToplevel(self.root)
                alert.title("⚠️ Threat Detected")
                alert.geometry("500x300")
                alert.attributes('-topmost', True)

                frame = ctk.CTkFrame(alert, fg_color=self.colors["red_dark"])
                frame.pack(fill="both", expand=True, padx=2, pady=2)

                title = ctk.CTkLabel(
                    frame,
                    text="⚠️ MALICIOUS PROCESS DETECTED",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color="white"
                )
                title.pack(pady=20)

                details = f"""PID: {proc_info['pid']}
Name: {proc_info['name']}
Path: {proc_info['exe']}

YARA Rule: {rule}
Threat Score: {threat_score}
Risk Level: {risk_level}"""

                details_label = ctk.CTkLabel(
                    frame,
                    text=details,
                    font=ctk.CTkFont(size=12),
                    justify="left"
                )
                details_label.pack(pady=10, padx=20)

                btn_close = ctk.CTkButton(
                    frame,
                    text="Close",
                    command=alert.destroy,
                    fg_color=self.colors["navy"],
                    hover_color=self.colors["dark_blue"]
                )
                btn_close.pack(pady=20)

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
            
            suspicious_text = "Yes" if conn.get('suspicious', False) else "No"
            tags = ('suspicious',) if conn.get('suspicious', False) else ()
            
            self.network_tree.insert(
                "", "end",
                values=(
                    conn.get('type', ''),
                    local_addr,
                    remote_addr,
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


# Main entry point
if __name__ == "__main__":
    app = ForensicAnalysisGUI()
    app.run()
