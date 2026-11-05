"""Report generator."""
import json
from datetime import datetime, timezone
from collections import Counter

def generate_report(alerts, total_flows, total_attacks):
    detections = sum(1 for a in alerts if a["attack_type"] != "BENIGN")
    by_sev = Counter(a["severity"] for a in alerts)
    by_type = Counter(a["attack_type"] for a in alerts)
    fp = sum(1 for a in alerts if a["is_anomaly"] and a["attack_type"] == "BENIGN")
    tp = sum(1 for a in alerts if a["is_anomaly"] and a["attack_type"] != "BENIGN")
    detection_rate = round(tp / max(total_attacks, 1) * 100, 1)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "total_flows": total_flows,
        "alerts_raised": detections,
        "detection_rate": detection_rate,
        "false_positives": fp,
        "true_positives": tp,
        "by_severity": dict(by_sev),
        "by_attack_type": dict(by_type),
    }
