
import yara
import os
from datetime import datetime
from yarwatch.imphash_db import find_family_by_imphash, update_imphash_family
from yarwatch.config import network_script
from yarwatch.pid_plugins import PID_PLUGINS
from datetime import datetime
from yarwatch.log_sync import get_desktop_log_path, copy_json_to_shared_folder
from yarwatch.scoring import calculate_threat_score as _score_module_func
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

def run_yara_file(file_path, gui, feature_extractor, logger):
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

    if gui:
        gui.update_collapsible_output(context["results"])

    if imphash and imphash != "N/A" and (rule != "No_YARA_Hit" or thq_family):
        update_imphash_family(rule if rule != "No_YARA_Hit" else thq_family, imphash)

    return ordered_results


# Keep local scoring helper for PID flow if needed (delegates to module + same multi-match bonus when used)
def calculate_threat_score(rule, strings_matched, process_name=None, vt_hits=0, thq_family=None, domains=None):
    base, level, reasons = _score_module_func(rule, strings_matched, process_name, vt_hits, thq_family, domains)
    # level already computed by module; we just return
    return base, level, reasons


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
        "rules": results.get("rules"),
        "yara_matches": results.get("yara_matches"),
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

    copy_json_to_shared_folder(get_desktop_log_path(), r"\\10.1.64.2\\pdc\\!Persistent_Folder\\YarWatchLogs")

def pid_yara_memory_plugin(ctx):
    logger = ctx["logger"]
    pid = ctx["pid"]
    results = ctx["results"]
