"""Detection engine with AlertEngine."""
import numpy as np, logging
from aegisq.config import DetectionConfig
from aegisq.detector.autoencoder import Autoencoder

logger = logging.getLogger("aegisq")

class AEGISQDetector:
    def __init__(self, config=None):
        self.config = config or DetectionConfig()
        self.model = Autoencoder(self.config.n_features, self.config.ae_encoding_dim, self.config.ae_lr)

    def fit(self, X):
        self.model.train(X, epochs=self.config.ae_epochs)
        return self

    def predict(self, X):
        recon = self.model.forward(X)
        mse = np.mean((X - recon) ** 2, axis=1)
        return mse

class AlertEngine:
    ATTACK_TYPES = {0: "BENIGN", 1: "DDoS", 2: "DATA_EXFIL", 3: "C2_BEACON", 4: "PORT_SCAN"}

    @staticmethod
    def analyze(scores, y_true, config):
        alerts = []
        threshold = config.anomaly_threshold
        for i, score in enumerate(scores):
            is_anomaly = score > threshold
            attack_type = AlertEngine.ATTACK_TYPES.get(y_true[i], "BENIGN")
            severity = "LOW"
            if score > config.severity_critical:
                severity = "CRITICAL"
            elif score > config.severity_high:
                severity = "HIGH"
            elif score > config.severity_medium:
                severity = "MEDIUM"
            alerts.append({
                "flow_id": i,
                "anomaly_score": float(score),
                "is_anomaly": bool(is_anomaly),
                "attack_type": attack_type,
                "severity": severity,
            })
        return alerts
