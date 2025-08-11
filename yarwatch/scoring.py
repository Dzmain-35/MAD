# yarwatch/scoring.py

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
        domain_bonus = len(domains) // 5
        if domain_bonus:
            score += domain_bonus
            reasons.append(f"Additional domain count bonus (+{domain_bonus})")

    if score >= 60:
        level = "Critical"
    elif score >= 40:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return score, level, reasons
