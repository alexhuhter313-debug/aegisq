"""Anomaly Detection Module — ML-based threat detection."""

import numpy as np
from typing import Any
from dataclasses import dataclass


@dataclass
class AnomalyResult:
    """Result from anomaly detection."""
    is_anomaly: bool
    score: float
    features: dict
    timestamp: float


class AnomalyDetector:
    """ML-based anomaly detector for security events."""

    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        self.model = None
        self._initialize_model()

    def _initialize_model(self):
        """Initialize the anomaly detection model."""
        # Simplified model for demo
        # In production, use IsolationForest or autoencoder
        self.model = "IsolationForest(contamination=0.1)"

    def detect(self, features: dict[str, Any]) -> AnomalyResult:
        """Detect anomalies in the input features."""
        import time

        # Simplified scoring for demo
        # In production, this would use the ML model
        score = self._calculate_anomaly_score(features)
        is_anomaly = score > self.threshold

        return AnomalyResult(
            is_anomaly=is_anomaly,
            score=score,
            features=features,
            timestamp=time.time(),
        )

    def _calculate_anomaly_score(self, features: dict[str, Any]) -> float:
        """Calculate anomaly score from features."""
        # Simplified scoring logic
        score = 0.0

        # High privilege escalation attempts
        if features.get("privilege_escalation", False):
            score += 0.4

        # Unusual network activity
        if features.get("network_anomaly", False):
            score += 0.3

        # Multiple failed logins
        failed_logins = features.get("failed_logins", 0)
        if failed_logins > 5:
            score += min(0.3, failed_logins * 0.05)

        # Unusual time
        hour = features.get("hour", 12)
        if hour < 6 or hour > 22:
            score += 0.1

        return min(1.0, score)

    def batch_detect(self, events: list[dict]) -> list[AnomalyResult]:
        """Detect anomalies in a batch of events."""
        return [self.detect(event) for event in events]


if __name__ == "__main__":
    detector = AnomalyDetector(threshold=0.7)

    # Test normal event
    normal = {"privilege_escalation": False, "network_anomaly": False, "failed_logins": 1, "hour": 14}
    result = detector.detect(normal)
    print(f"Normal event: anomaly={result.is_anomaly}, score={result.score:.2f}")

    # Test suspicious event
    suspicious = {"privilege_escalation": True, "network_anomaly": True, "failed_logins": 10, "hour": 3}
    result = detector.detect(suspicious)
    print(f"Suspicious event: anomaly={result.is_anomaly}, score={result.score:.2f}")
