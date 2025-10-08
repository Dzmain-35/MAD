
import os
import subprocess
import yara
from yarwatch.utils import calculate_md5, calculate_sha256, is_pe_file
from yarwatch.imphash_db import find_family_by_imphash, update_imphash_family
from yarwatch.dns_extractor_memory import DNSExtractor
from yarwatch.config import vt_script, thq_script
from yarwatch.cache_utils import read_cache, write_cache

dns_extractor = DNSExtractor()

def scan_yara_file_plugin(ctx):
    logger = ctx["logger"]
    file_path = ctx["file_path"]
    fe = ctx["feature_extractor"]
    results = ctx["results"]

    # Ensure aggregation containers exist (so later plugins/UI can rely on them)
    results.setdefault("yara_matches", [])
    results.setdefault("rules", [])
    results.setdefault("strings", [])  # will hold a de-duplicated union across all rules

    def callback(data):
        return yara_callback(data, ctx)

    matches = get_yara_rules().match(
        file_path,
        callback=callback,
        which_callbacks=yara.CALLBACK_MATCHES
    )

    results["matches_found"] = bool(matches)


def scan_thq_plugin(ctx):
    logger = ctx["logger"]
    results = ctx["results"]
    file_md5 = results.get("md5")

    if not file_md5:
        file_md5 = calculate_md5(ctx["file_path"])
        results["md5"] = file_md5

    cached = read_cache("thq", file_md5)
    if cached:
        thq_output = cached["output"]
        results["thq_family"] = cached["family"]
    else:
        thq_output = subprocess.run(["python", thq_script, file_md5], capture_output=True, text=True).stdout

        family = None
        if "Family:" in thq_output:
            try:
                family = thq_output.split("Family:")[1].splitlines()[0].strip()
            except:
                family = None

        results["thq_family"] = family
        write_cache("thq", file_md5, {"output": thq_output, "family": family})

def scan_vt_plugin(ctx):
    logger = ctx["logger"]
    file_path = ctx["file_path"]
    results = ctx["results"]
    file_md5 = results.get("md5") or calculate_md5(file_path)
    results["md5"] = file_md5

    cached = read_cache("vt", file_md5)
    if cached:
        vt_output = cached["output"]
        hits = cached["hits"]
    else:
        vt_output = subprocess.run(["python", vt_script, file_path], capture_output=True, text=True).stdout
        hits = 0
        try:
            for line in vt_output.splitlines():
                if "VT Detection" in line:
                    hits = int(line.split(":")[1].split("/")[0].strip())
                    break
        except:
            pass
        write_cache("vt", file_md5, {"output": vt_output, "hits": hits})
        logger.log(vt_output)

    results["vt_hits"] = hits


def scan_dns_plugin(ctx):
    file_path = ctx["file_path"]
    results = ctx["results"]
    try:
        domains, removed, _ = dns_extractor.extract_from_file(file_path, output_file=None)
        # keep only suspicious side (first list)
        results["dns_domains"] = domains or []
    except Exception as e:
        ctx["logger"].log(f"[DNS ERROR] {e}")
        results["dns_domains"] = []

# --- YARA rules loader (unchanged) ---
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

# --- Callback now aggregates ALL matches instead of overwriting ---
def yara_callback(data, ctx):
    rule = data.get("rule")
    logger = ctx["logger"]
    fe = ctx["feature_extractor"]
    file_path = ctx["file_path"]
    results = ctx["results"]

    # pull strings (unique, readable)
    strings_matched = set()
    for s in data.get("strings", []):
        for instance in getattr(s, "instances", []):
            try:
                strings_matched.add(instance.matched_data.decode("utf-8", errors="ignore"))
            except Exception:
                continue

    # persist per-rule artifacts
    fe.ensure_rule_directory(rule)
    fe.save_hashes(rule, file_path)
    fe.save_strings(rule, sorted(strings_matched))

    # --- aggregate per-rule in results ---
    results.setdefault("yara_matches", [])
    results.setdefault("rules", [])
    results.setdefault("strings", [])

    # append structured match
    results["yara_matches"].append({
        "rule": rule,
        "strings": sorted(strings_matched),
        "meta": dict(data.get("meta") or {}),
    })

    # keep flat lists for backward-compat + ease of display
    if rule not in results["rules"]:
        results["rules"].append(rule)

    merged = set(results.get("strings", []))
    merged.update(strings_matched)
    results["strings"] = sorted(merged)

    # maintain a comma-joined "rule" for code that expects a single string
    results["rule"] = ", ".join(results["rules"])

    results["matches_found"] = True

    # continue scanning other rules
    return yara.CALLBACK_CONTINUE
