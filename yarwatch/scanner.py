import yara
import os
from datetime import datetime
from yarwatch.imphash_db import find_family_by_imphash, update_imphash_family
from yarwatch.config import network_script
from yarwatch.pid_plugins import PID_PLUGINS
from datetime import datetime
from yarwatch.log_sync import get_desktop_log_path, copy_json_to_shared_folder
from yarwatch.scoring import calculate_threat_score
from yarwatch.scanner_plugins import (
    scan_yara_file_plugin,
    scan_thq_plugin,
    scan_vt_plugin,
    scan_dns_plugin,
)

SCAN_PLUGINS = [
    scan_yara_file_plugin,
    scan_thq_plugin,
    scan_vt_plugin,
    scan_dns_plugin,
]

def run_yara_file(file_path, dashboard_gui, gui, feature_extractor, logger):
    context = {
        "file_path": file_path,
        "logger": logger,
        "feature_extractor": feature_extractor,
        "gui": gui,
        "results": {
            "target_type": "file",
            "target": file_path,
            "timestamp": datetime.now().isoformat(),
            "matches_found": False,
        },
    }
    file_size = os.path.getsize(file_path)
    context["results"]["size"] = file_size
    context["results"]["file_name"] = os.path.basename(file_path)

    for plugin in SCAN_PLUGINS:
        try:
            plugin(context)
        except Exception as e:
            logger.log(f"[PLUGIN ERROR] {plugin.__name__}: {e}")

    results = context["results"]

    # === Enrich results ===
    file_sha256 = results.get("sha256")
    if not file_sha256:
        from yarwatch.utils import calculate_sha256
        results["sha256"] = calculate_sha256(file_path)

    imphash = feature_extractor.calculate_imphash(file_path)
    results["imphash"] = imphash

    imphash_matches = []
    fam = find_family_by_imphash(imphash)
    if fam:
        imphash_matches.append(fam)
        logger.log(f"Imphash matched known family: {fam}")
    results["imphash_matches"] = imphash_matches

    rule = results.get("rule", "No_YARA_Hit")
    vt_hits = results.get("vt_hits", 0)
    thq_family = results.get("thq_family")
    dns_domains = results.get("dns_domains", [])
    strings = results.get("strings", [])

    score, level, reasons = calculate_threat_score(rule, strings, None, vt_hits, thq_family, dns_domains)
    results.update({
        "threat_score": score,
        "risk_level": level,
        "score_reasons": reasons,
    })

    ordered_results = {
    "target_type": results.get("target_type"),
    "target": results.get("target"),
    "timestamp": results.get("timestamp"),
    "matches_found": results.get("matches_found"),
    "file_name": results.get("file_name"),
    "strings": results.get("strings"),
    "rule": results.get("rule"),
    "md5": results.get("md5"),
    "sha256": results.get("sha256"),
    "size": results.get("size"),
    "imphash": results.get("imphash"),
    "imphash_matches": results.get("imphash_matches"),
    "thq_family": results.get("thq_family"),
    "vt_hits": results.get("vt_hits"),
    "dns_domains": results.get("dns_domains"),
    "threat_score": results.get("threat_score"),
    "risk_level": results.get("risk_level"),
    "score_reasons": results.get("score_reasons"),
}

    logger.log_json(ordered_results)
    copy_json_to_shared_folder(get_desktop_log_path(), r"\\10.1.64.2\pdc\!Persistent_Folder\YarWatchLogs")
    


    # Learn imphash
    if imphash and imphash != "N/A" and (rule != "No_YARA_Hit" or thq_family):
        update_imphash_family(rule if rule != "No_YARA_Hit" else thq_family, imphash)
        # === Append file to case (if GUI has case manager) ===
        # === Append file to case (if GUI has case manager) ===
    # Learn imphash
    if imphash and imphash != "N/A" and (rule != "No_YARA_Hit" or thq_family):
        update_imphash_family(rule if rule != "No_YARA_Hit" else thq_family, imphash)

    # Append file to current case (if dashboard supports it)
    file_info = {
        "file_name": os.path.basename(file_path),
        "md5": results.get("md5", "N/A"),
        "sha256": results.get("sha256", "N/A"),
        "size": results.get("size", 0),
        "imphash": results.get("imphash", "N/A"),
        "rule": results.get("rule", "None"),
        "vt_hits": results.get("vt_hits", 0),
        "thq_family": results.get("thq_family", "None"),
        "threat_score": results.get("threat_score", 0),
        "risk_level": results.get("risk_level", "Low"),
        "strings": results.get("strings", [])
    }

    if hasattr(dashboard_gui, "case_manager"):
        dashboard_gui.case_manager.add_file_to_case(file_info)

    if hasattr(dashboard_gui, "update_attached_files_panel"):
        dashboard_gui.update_attached_files_panel()


    

def calculate_threat_score(rule, strings_matched, process_name=None, vt_hits=0, thq_family=None, domains=None):
    score = 0
    reasons = []
    domains = domains or []
    rule = rule.lower() if rule else ""

    if rule != "no_yara_hit":
        score += 60
        reasons.append(f"Matched YARA rule '{rule}' (+60)")
    if thq_family:
        score += 40
        reasons.append(f"THQ flagged family '{thq_family}' (+40)")
    if vt_hits >= 10:
        score += 20
        reasons.append("VT flagged by ≥10 vendors (+20)")
    elif vt_hits >= 5:
        score += 10
        reasons.append("VT flagged by 5–9 vendors (+10)")
    elif vt_hits == 0:
        score -= 20
        reasons.append("No VT hits (-20)")
    if domains:
        score += 2
        reasons.append(f"Suspicious DNS activity ({len(domains)} domains) (+2)")
        bonus = len(domains) // 5
        if bonus:
            score += bonus
            reasons.append(f"Domain count bonus (+{bonus})")

    if score >= 60:
        level = "Critical"
    elif score >= 40:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return score, level, reasons



def run_yara_pid(pid, gui, feature_extractor, logger):
    context = {
        "pid": int(pid),
        "logger": logger,
        "feature_extractor": feature_extractor,
        "gui": gui,
        "results": {
            "target_type": "pid",
            "target": str(pid),
            "timestamp": datetime.now().isoformat(),
            "matches_found": False,
        },
    }

    for plugin in PID_PLUGINS:
        try:
            plugin(context)
        except Exception as e:
            logger.log(f"[PLUGIN ERROR] {plugin.__name__}: {e}")

    results = context["results"]
    ordered_results = {
    "target_type": results.get("target_type"),
    "target": results.get("target"),
    "timestamp": results.get("timestamp"),
    "matches_found": results.get("matches_found"),
    "file_name": results.get("file_name"),
    "strings": results.get("strings"),
    "rule": results.get("rule"),
    "md5": results.get("md5"),
    "sha256": results.get("sha256"),
    "size": results.get("size"),
    "imphash": results.get("imphash"),
    "imphash_matches": results.get("imphash_matches"),
    "thq_family": results.get("thq_family"),
    "vt_hits": results.get("vt_hits"),
    "dns_domains": results.get("dns_domains"),
    "threat_score": results.get("threat_score"),
    "risk_level": results.get("risk_level"),
    "score_reasons": results.get("score_reasons"),
}

    logger.log_json(ordered_results)


    copy_json_to_shared_folder(get_desktop_log_path(), r"\\10.1.64.2\pdc\!Persistent_Folder\YarWatchLogs")

def pid_yara_memory_plugin(ctx):
    logger = ctx["logger"]
    pid = ctx["pid"]
    results = ctx["results"]






