import json
from pathlib import Path

test_cases = [
    {"id": f"LEGIT-{i:02d}", "login_risk": "low",
     "ip": f"192.0.2.{i}"}
    for i in range(1, 11)
]

suspicious_ips = ["203.0.113.10"]
results = []

for case in test_cases:
    blocked = (
        case["login_risk"] == "high"
        or case["ip"] in suspicious_ips
    )
    results.append({
        **case,
        "result": "BLOCK" if blocked else "ALLOW",
        "expected": "ALLOW",
        "false_positive": blocked
    })

false_positives = sum(r["false_positive"] for r in results)
summary = {
    "test_type": "Local risk-rule test simulation",
    "total_tests": len(results),
    "allowed": sum(r["result"] == "ALLOW" for r in results),
    "false_positives": false_positives,
    "false_positive_rate_percent": false_positives / len(results) * 100,
    "results": results
}

Path("evidence/false_positive_test_results.json").write_text(
    json.dumps(summary, indent=2)
)
print(json.dumps(summary, indent=2))
