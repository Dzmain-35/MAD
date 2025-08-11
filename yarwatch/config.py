import os

# === Paths to external scripts ===
SCRIPTS_DIR = r"\\10.1.64.2\pdc\!Persistent_Folder\1YarWatch1\YarWatch_Scripts"

network_script = os.path.join(SCRIPTS_DIR, "PHRem.py")
yara_rules_directory = os.path.join(SCRIPTS_DIR, "YDAMN")
vt_script = os.path.join(SCRIPTS_DIR, "VT.PY")
watch_script = os.path.join(SCRIPTS_DIR, "WatchNoti.py")
yar_report_script = os.path.join(SCRIPTS_DIR, "YarReport.py")
ioc_search_script = os.path.join(SCRIPTS_DIR, "IOC_Search.py")
daily_mal_script = os.path.join(SCRIPTS_DIR, "Daily_Mal.py")
malcop_script = os.path.join(SCRIPTS_DIR, "MalCop.py")
thq_script = os.path.join(SCRIPTS_DIR, "thq.py")
scan_gui_script = os.path.join(SCRIPTS_DIR, "scan_gui.py")

# === Output and resource directories ===
log_file_path = r"C:\\Users\\REM\\Desktop\\YarWatch_Data.txt"
json_log_path = r"C:\\Users\\REM\\Desktop\\YarWatch_Log.json"
mal_data_dir = r"\\10.1.64.2\pdc\!Persistent_Folder\Mal_Data"
dump_output_dir = r"C:\\Users\\REM\\Desktop"

# === UI Resources ===
icon_path = os.path.join(SCRIPTS_DIR, "Y30.ico")
logo_path = os.path.join(SCRIPTS_DIR, "Y30.png")

yara_file_exts = (".yara", ".yar")

disallowed_processes = [
    "dllhost.exe", "py.exe", "chrome.exe", "python.exe",
    "procdump64.exe","procdump.exe", "updater.exe", "wscript.exe",
    "powershell.exe", "cmd.exe", "SearchProtocolHost.exe","searchfilterhost.exe","backgroundTaskHost.exe","ipconfig.exe","ConEmuC.exe",
]
 
safe_windows_processes = [
    "SearchUI.exe", "explorer.exe", "RuntimeBroker.exe",
    "vmtoolsd.exe", "python.exe","msfeedssync.exe","wmic.exe","ielowutil.exe",
]
