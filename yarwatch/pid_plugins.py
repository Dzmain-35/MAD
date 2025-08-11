import os
import psutil
import yara
import subprocess
from datetime import datetime
from yarwatch.dns_extractor_memory import DNSExtractor
from yarwatch.config import network_script
from yarwatch.scoring import calculate_threat_score

dns_extractor = DNSExtractor()

def pid_process_info_plugin(ctx):
    pid = ctx["pid"]
    logger = ctx["logger"]
    results = ctx["results"]

    try:
        proc = psutil.Process(pid)
        results["process_name"] = proc.name()
        results["create_time"] = datetime.fromtimestamp(proc.create_time()).isoformat()

    except Exception as e:
        results["process_name"] = "unknown"
        results["create_time"] = None
        logger.log(f"[ERROR] Failed to get process info: {e}")

def pid_yara_memory_plugin(ctx):
    logger = ctx["logger"]
    pid = ctx["pid"]
    results = ctx["results"]

    def callback(data):
        return yara_callback(data, ctx)

    try:
        matches = get_yara_rules().match(pid=pid, callback=callback, which_callbacks=yara.CALLBACK_MATCHES)
        results["matches_found"] = bool(matches)

        if matches and not results.get("rule"):
            m = matches[0]
            results["rule"] = m.rule
            results["strings"] = sorted(set(s[2] for s in m.strings if isinstance(s, tuple) and len(s) == 3))
    except Exception as e:
        logger.log(f"[ERROR] YARA memory scan failed: {e}")


def pid_yara_fallback_plugin(ctx):
    logger = ctx["logger"]
    pid = ctx["pid"]
    results = ctx["results"]
    feature_extractor = ctx["feature_extractor"]

    rule = "No_YARA_Hit"
    results.setdefault("strings", [])
    results.setdefault("rule", rule)

    logger.log("Dumping memory and extracting strings for fallback YARA scan...")

    try:
        # ✅ 1. Extract and save full memory strings to correct folder
        all_strings = feature_extractor.extract_strings_from_pid(pid)
        feature_extractor.save_strings("NoMatch", all_strings)

        # ✅ 2. Write full dump to temp file for scanning
        os.makedirs("temp", exist_ok=True)
        temp_path = os.path.join("temp", f"pid_{pid}_fallback.txt")
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(all_strings))

        # ✅ 3. Compile and run YARA against the dump
        rules = yara.compile(filepaths={
            os.path.splitext(f)[0]: os.path.join(feature_extractor.mal_data_path, f)
            for f in os.listdir(feature_extractor.mal_data_path)
            if f.endswith(('.yara', '.yar'))
        })

        matches = rules.match(filepath=temp_path)

        if matches:
            m = matches[0]
            rule = m.rule
            matched_strings = sorted(set(
                s[2] for s in m.strings if isinstance(s, tuple) and len(s) == 3
            ))

            results["rule"] = rule
            results["matches_found"] = True
            results["strings"] = matched_strings[:10]  # ✅ Only show these in GUI

            logger.log(f"[INFO] Matched {len(matched_strings)} strings")
            logger.log("===== YARA Match (Fallback) =====")
            logger.log(f"Matched Rule: {rule}")
            for s in results["strings"]:
                logger.log(f"String Match: {s}")
        else:
            logger.log("No matches found in fallback YARA scan.")

    except Exception as e:
        logger.log(f"[PLUGIN ERROR] pid_yara_fallback_plugin: {e}")


def pid_network_script_plugin(ctx):
    logger = ctx["logger"]
    pid = ctx["pid"]
    results = ctx["results"]

    if not results.get("matches_found"):
        return  # Only run if YARA match

    try:
        import psutil
        proc = psutil.Process(pid)
        proc_name = proc.name()
    except Exception as e:
        logger.log(f"[ERROR] Could not get process name for PID {pid}: {e}")
        proc_name = None

    if not proc_name:
        return

    logger.log("\n===== Network Analysis (PHRem) =====")
    try:
        # Run network script and capture output
        proc = subprocess.run(["python", network_script], capture_output=True, text=True)
        output = proc.stdout.strip()

        # Only include blocks for the matched process name
        filtered_blocks = []
        current_block = []

        for line in output.splitlines():
            if line.startswith("Connection"):
                if current_block:
                    block_text = "\n".join(current_block)
                    if proc_name.lower() in block_text.lower():
                        filtered_blocks.append(block_text)
                    current_block = []
            current_block.append(line)

        # Add last block
        if current_block:
            block_text = "\n".join(current_block)
            if proc_name.lower() in block_text.lower():
                filtered_blocks.append(block_text)

        if filtered_blocks:
            result_text = "\n\n".join(filtered_blocks)
            logger.log(result_text)
            results["network_output"] = result_text
        else:
            logger.log(f"No network activity found for PID {pid} ({proc_name})")
            results["network_output"] = "No active connections found."

    except Exception as e:
        logger.log(f"[ERROR] Network script failed: {e}")
        results["network_output"] = None

def pid_dns_plugin(ctx):
    logger = ctx["logger"]
    pid = ctx["pid"]
    results = ctx["results"]

    try:
        domains, _, _ = dns_extractor.extract_from_process(pid)
        results["dns_domains"] = domains
    except Exception as e:
        logger.log(f"[ERROR] DNS extraction failed: {e}")
        results["dns_domains"] = []

def pid_threat_score_plugin(ctx):
    results = ctx["results"]

    score, level, reasons = calculate_threat_score(
        results.get("rule", "No_YARA_Hit"),
        results.get("strings", []),
        process_name=results.get("process_name", "unknown"),
        vt_hits=0,
        thq_family=results.get("thq_family"),
        domains=results.get("dns_domains", [])
    )

    results["threat_score"] = score
    results["risk_level"] = level
    results["score_reasons"] = reasons

# --- YARA Callback ---
def yara_callback(data, ctx):
    rule = data.get('rule')
    logger = ctx["logger"]
    results = ctx["results"]
    fe = ctx["feature_extractor"]
    pid = ctx["pid"]

    strings_matched = set()
    for s in data['strings']:
        for instance in s.instances:
            try:
                strings_matched.add(instance.matched_data.decode('utf-8', errors='ignore'))
            except:
                continue

    # === Log YARA match event ===
    logger.log(f"[INFO] YARA match callback triggered for rule: {rule}")
    logger.log(f"[INFO] Matched {len(strings_matched)} strings")

    # === Save full dumped strings to mal_data_dir/<rule> ===
    full_strings = fe.extract_strings_from_pid(pid, matched_rule=rule, logger=logger)

    results["rule"] = rule
    results["strings"] = sorted(strings_matched)  # Keep matched strings in results
    results["matches_found"] = True

    return yara.CALLBACK_CONTINUE



# --- YARA Rule Loader ---
def get_yara_rules():
    import yarwatch.config as config
    if not hasattr(get_yara_rules, "_rules"):
        rule_dict = {
            os.path.splitext(f)[0]: os.path.join(config.yara_rules_directory, f)
            for f in os.listdir(config.yara_rules_directory)
            if f.endswith(('.yara', '.yar'))
        }
        get_yara_rules._rules = yara.compile(filepaths=rule_dict)
    return get_yara_rules._rules

# --- Plugin Chain ---
PID_PLUGINS = [
    pid_process_info_plugin,
    pid_yara_memory_plugin,
    pid_yara_fallback_plugin,
    pid_network_script_plugin,
    pid_dns_plugin,
    pid_threat_score_plugin,
]
