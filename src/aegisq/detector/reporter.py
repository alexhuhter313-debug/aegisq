"""Report generator."""
import json
from datetime import datetime, UTC
from collections import Counter
def generate_report(alerts,total_flows,total_attacks):
    detections=sum(1 for a in alerts if a["attack_type"]!="BENIGN")
    by_sev=Counter(a["severity"] for a in alerts)
    by_type=Counter(a["attack_type"] for a in alerts)
    r={"timestamp":datetime.now(UTC).isoformat(),"total_flows":total_flows,"total_attacks":total_attacks,"alerts_raised":len(alerts),"detection_rate":round(detections/max(total_attacks,1)*100,1),"false_positives":max(0,len(alerts)-total_attacks),"by_severity":dict(by_sev),"by_attack_type":dict(by_type)}
    print(json.dumps(r,indent=2))
    with open("aegisq_report.json","w") as f:json.dump(r,f,indent=2)
    return r
