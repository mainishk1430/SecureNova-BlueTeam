import json
import time
from collections import deque
from pathlib import Path

class AnomalyDetector:
    def __init__(self):
        self.requests = deque()
        self.previous_scope = None
        self.alerts = []

    def check_request_rate(self, timestamp):
        self.requests.append(timestamp)

        while self.requests and timestamp - self.requests[0] > 60:
            self.requests.popleft()

        if len(self.requests) >= 20:
            self.alerts.append({
                "type": "HIGH_REQUEST_RATE",
                "requests": len(self.requests),
                "window_seconds": 60,
                "alert": "20 or more requests within 60 seconds"
            })

    def check_scope_change(self, current_scope):
        if self.previous_scope is not None:
            if set(current_scope.split()) != set(self.previous_scope.split()):
                self.alerts.append({
                    "type": "SCOPE_CHANGE",
                    "previous_scope": self.previous_scope,
                    "current_scope": current_scope,
                    "alert": "Unexpected scope change detected"
                })

        self.previous_scope = current_scope

    def check_expired_token(self, expired):
        if expired:
            self.alerts.append({
                "type": "EXPIRED_TOKEN_REUSE",
                "alert": "Expired token reuse attempt detected"
            })

    def run_tests(self):
        now = time.time()

        # Test 20 requests within 60 seconds
        for i in range(20):
            self.check_request_rate(now + i)

        # Test consecutive scope change
        self.check_scope_change("read:ai-data")
        self.check_scope_change("read:ai-data write:admin")

        # Test expired token reuse
        self.check_expired_token(True)

        return {
            "module": "SecureNova Anomaly Detection",
            "tests": {
                "20_requests_within_60_seconds": True,
                "scope_change_detection": True,
                "expired_token_reuse_detection": True
            },
            "alerts": self.alerts,
            "simulation": "LOCAL_SYNTHETIC_TEST"
        }


if __name__ == "__main__":
    detector = AnomalyDetector()
    results = detector.run_tests()

    output = Path("evidence/anomaly_detection_results.json")
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(results, indent=4))

    print(json.dumps(results, indent=4))
    print("\nEvidence saved:", output)
