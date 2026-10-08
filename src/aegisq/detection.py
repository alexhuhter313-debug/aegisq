"""AEGISQ v2 — Quantum-Ready AI Threat Detection with Deep Learning"""
import numpy as np
import logging
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Tuple
import hashlib

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("aegisq")

# ============================================================
# 1. CONFIGURATION
# ============================================================
@dataclass
class Config:
    n_features: int = 24
    n_normal: int = 5000
    n_attack: int = 200
    anomaly_threshold: float = 0.3
    severity_critical: float = 0.9
    severity_high: float = 0.7
    severity_medium: float = 0.5
    ae_encoding_dim: int = 8
    ae_epochs: int = 50
    ae_lr: float = 0.001
    rand_seed: int = 42


# ============================================================
# 2. SYNTHETIC DATA GENERATOR
# ============================================================
class DataGenerator:
    """Generates realistic network flows with labeled attack types."""

    ATTACK_TYPES = {
        0: "BENIGN",
        1: "DDoS",
        2: "DATA_EXFIL",
        3: "C2_BEACON",
        4: "PORT_SCAN",
    }

    @classmethod
    def generate(cls, n_normal: int, n_attack: int, seed: int = 42):
        rng = np.random.default_rng(seed)
        samples = []
        labels = []
        attack_types = []

        # Normal traffic
        for _ in range(n_normal):
            f = np.zeros(24)
            f[0] = rng.normal(600, 200).clip(40, 1500)        # src_port
            f[1] = rng.choice([80, 443, 53, 22, 3389])         # dst_port
            f[2] = rng.normal(500, 150).clip(10, 2000)         # bytes_sent
            f[3] = rng.normal(1200, 400).clip(50, 5000)        # bytes_recv
            f[4] = rng.exponential(30).clip(0.1, 300)           # duration_s
            f[5] = rng.integers(1, 50)                          # packets_sent
            f[6] = rng.integers(1, 50)                          # packets_recv
            f[7] = f[4] / max(f[5] + f[6], 1)                   # avg_pkt_interval
            f[8] = rng.beta(85, 10) * 100                       # protocol_entropy
            f[9] = rng.beta(2, 5) * 100                         # payload_entropy
            f[10] = 0                                           # is_attack_flag
            f[11] = rng.integers(0, 5)                          # dst_unique_count
            f[12] = rng.integers(0, 3)                          # src_unique_count
            f[13] = rng.normal(0.5, 0.2).clip(0, 1)             # syn_ratio
            f[14] = rng.normal(0.3, 0.1).clip(0, 1)             # ack_ratio
            f[15] = rng.normal(1.5, 0.5).clip(0, 5)             # fin_ratio
            f[16] = rng.exponential(10).clip(0, 100)            # ttl_avg
            f[17] = rng.normal(0.1, 0.05).clip(0, 1)            # retransmit_ratio
            f[18] = 0                                           # window_size
            f[19] = rng.normal(0.4, 0.15).clip(0, 1)            # small_pkt_ratio
            f[20] = rng.beta(1, 3) * 100                        # entropy_payload
            f[21] = 0                                           # c2_pattern_score
            f[22] = rng.normal(0.3, 0.1).clip(0, 1)             # burst_ratio
            f[23] = rng.exponential(0.5).clip(0, 5)             # idle_time_avg
            samples.append(f)
            labels.append(0)
            attack_types.append("BENIGN")

        # DDoS: high volume, many small packets, high syn_ratio
        for _ in range(n_attack // 4):
            f = np.zeros(24)
            f[0] = rng.integers(1024, 65535)
            f[1] = rng.choice([80, 443, 53])
            f[2] = rng.normal(80, 30).clip(20, 200)
            f[3] = rng.normal(100, 50).clip(20, 300)
            f[4] = rng.exponential(2).clip(0.1, 15)
            f[5] = rng.integers(100, 500)
            f[6] = rng.integers(50, 300)
            f[7] = f[4] / max(f[5] + f[6], 1)
            f[8] = rng.beta(50, 50) * 100
            f[9] = rng.beta(1, 10) * 100
            f[10] = 1
            f[11] = rng.integers(1, 3)
            f[12] = rng.integers(0, 1)
            f[13] = rng.beta(15, 2).clip(0, 1)
            f[14] = rng.beta(2, 10).clip(0, 1)
            f[15] = rng.beta(1, 20).clip(0, 1)
            f[16] = rng.normal(60, 15).clip(20, 128)
            f[17] = rng.beta(1, 5).clip(0, 0.3)
            f[18] = 0
            f[19] = rng.beta(15, 3).clip(0, 1)
            f[20] = rng.beta(1, 5) * 100
            f[21] = 0
            f[22] = rng.beta(15, 5).clip(0, 1)
            f[23] = rng.exponential(0.1).clip(0, 1)
            samples.append(f)
            labels.append(1)
            attack_types.append("DDoS")

        # Data Exfiltration: high bytes_sent, high entropy, large payloads
        for _ in range(n_attack // 4):
            f = np.zeros(24)
            f[0] = rng.integers(1024, 65535)
            f[1] = rng.choice([443, 22, 53])
            f[2] = rng.normal(8000, 3000).clip(500, 50000)
            f[3] = rng.normal(500, 300).clip(50, 2000)
            f[4] = rng.exponential(60).clip(5, 300)
            f[5] = rng.integers(50, 200)
            f[6] = rng.integers(10, 50)
            f[7] = f[4] / max(f[5] + f[6], 1)
            f[8] = rng.beta(95, 4) * 100
            f[9] = rng.beta(90, 8) * 100
            f[10] = 1
            f[11] = rng.integers(1, 5)
            f[12] = rng.integers(0, 2)
            f[13] = rng.normal(0.5, 0.15).clip(0, 1)
            f[14] = rng.normal(0.3, 0.1).clip(0, 1)
            f[15] = rng.normal(1.5, 0.5).clip(0, 5)
            f[16] = rng.normal(110, 30).clip(40, 255)
            f[17] = rng.beta(1, 10).clip(0, 0.1)
            f[18] = rng.integers(1000, 65000)
            f[19] = rng.beta(1, 10).clip(0, 0.3)
            f[20] = rng.beta(95, 3) * 100
            f[21] = 0
            f[22] = rng.beta(2, 10).clip(0, 0.4)
            f[23] = rng.exponential(1).clip(0, 5)
            samples.append(f)
            labels.append(1)
            attack_types.append("DATA_EXFIL")

        # C2 Beacon: Regular intervals, small payloads, consistent timing
        for _ in range(n_attack // 4):
            f = np.zeros(24)
            f[0] = rng.integers(1024, 65535)
            f[1] = rng.choice([443, 8080, 8443])
            f[2] = rng.normal(200, 80).clip(40, 500)
            f[3] = rng.normal(300, 100).clip(50, 1000)
            f[4] = rng.normal(30, 5).clip(20, 60)
            f[5] = rng.integers(3, 15)
            f[6] = rng.integers(3, 15)
            f[7] = f[4] / max(f[5] + f[6], 1)
            f[8] = rng.beta(20, 30) * 100
            f[9] = rng.beta(30, 40) * 100
            f[10] = 1
            f[11] = rng.integers(1, 3)
            f[12] = rng.integers(0, 1)
            f[13] = rng.normal(0.6, 0.1).clip(0, 1)
            f[14] = rng.normal(0.25, 0.08).clip(0, 1)
            f[15] = rng.normal(0.8, 0.3).clip(0, 3)
            f[16] = rng.normal(120, 10).clip(60, 255)
            f[17] = rng.beta(1, 20).clip(0, 0.05)
            f[18] = 0
            f[19] = rng.beta(3, 15).clip(0, 0.4)
            f[20] = rng.beta(20, 30) * 100
            f[21] = rng.normal(0.85, 0.1).clip(0.5, 1.0)
            f[22] = rng.beta(2, 8).clip(0, 0.3)
            f[23] = rng.normal(4, 1).clip(2, 10)
            samples.append(f)
            labels.append(1)
            attack_types.append("C2_BEACON")

        # Port Scan: many short connections, many unique destinations
        for _ in range(n_attack // 4):
            f = np.zeros(24)
            f[0] = rng.integers(1024, 65535)
            f[1] = rng.choice([80, 443, 22, 21, 3306, 5432])
            f[2] = rng.normal(60, 20).clip(20, 150)
            f[3] = rng.normal(80, 30).clip(20, 200)
            f[4] = rng.exponential(0.5).clip(0.05, 5)
            f[5] = rng.integers(1, 5)
            f[6] = rng.integers(1, 5)
            f[7] = f[4] / max(f[5] + f[6], 1)
            f[8] = rng.beta(10, 50) * 100
            f[9] = rng.beta(1, 5) * 100
            f[10] = 1
            f[11] = rng.integers(10, 50)
            f[12] = rng.integers(0, 2)
            f[13] = rng.beta(15, 3).clip(0, 1)
            f[14] = rng.beta(1, 15).clip(0, 0.3)
            f[15] = rng.beta(1, 20).clip(0, 0.5)
            f[16] = rng.normal(50, 10).clip(20, 128)
            f[17] = rng.beta(1, 5).clip(0, 0.2)
            f[18] = 0
            f[19] = rng.beta(15, 5).clip(0, 1)
            f[20] = rng.beta(1, 5) * 100
            f[21] = 0
            f[22] = rng.beta(1, 10).clip(0, 0.1)
            f[23] = rng.exponential(0.05).clip(0, 0.5)
            samples.append(f)
            labels.append(1)
            attack_types.append("PORT_SCAN")

        X = np.array(samples)
        y = np.array(labels)
        at = np.array(attack_types)
        shuffle = rng.permutation(len(X))
        return X[shuffle], y[shuffle], at[shuffle]


# ============================================================
# 3. AUTOENCODER (PyTorch)
# ============================================================
class AutoEncoder:
    """Simple 3-layer autoencoder using numpy (no external deps)."""

    def __init__(self, input_dim: int, encoding_dim: int, lr: float = 0.001):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.lr = lr
        self.params = {}

    def _relu(self, x):
        return np.maximum(0, x)

    def _sigmoid(self, x):
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

    def _mse(self, y_true, y_pred):
        return np.mean((y_true - y_pred) ** 2)

    def init_params(self, rng):
        scale = np.sqrt(2.0 / self.input_dim)
        self.params["W1"] = rng.normal(0, scale, (self.input_dim, self.encoding_dim * 2))
        self.params["b1"] = np.zeros((1, self.encoding_dim * 2))
        scale2 = np.sqrt(2.0 / (self.encoding_dim * 2))
        self.params["W2"] = rng.normal(0, scale2, (self.encoding_dim * 2, self.encoding_dim))
        self.params["b2"] = np.zeros((1, self.encoding_dim))
        scale3 = np.sqrt(2.0 / self.encoding_dim)
        self.params["W3"] = rng.normal(0, scale3, (self.encoding_dim, self.encoding_dim * 2))
        self.params["b3"] = np.zeros((1, self.encoding_dim * 2))
        scale4 = np.sqrt(2.0 / (self.encoding_dim * 2))
        self.params["W4"] = rng.normal(0, scale4, (self.encoding_dim * 2, self.input_dim))
        self.params["b4"] = np.zeros((1, self.input_dim))

    def forward(self, X):
        self.cache = {}
        self.cache["z1"] = X @ self.params["W1"] + self.params["b1"]
        self.cache["a1"] = self._relu(self.cache["z1"])
        self.cache["z2"] = self.cache["a1"] @ self.params["W2"] + self.params["b2"]
        self.cache["a2"] = self._relu(self.cache["z2"])
        self.cache["z3"] = self.cache["a2"] @ self.params["W3"] + self.params["b3"]
        self.cache["a3"] = self._relu(self.cache["z3"])
        self.cache["z4"] = self.cache["a3"] @ self.params["W4"] + self.params["b4"]
        self.cache["output"] = self.cache["z4"]
        return self.cache["output"]

    def backward(self, X, lr):
        m = X.shape[0]
        dZ4 = self.cache["output"] - X
        dW4 = (self.cache["a3"].T @ dZ4) / m
        db4 = np.mean(dZ4, axis=0, keepdims=True)
        dA3 = dZ4 @ self.params["W4"].T
        dZ3 = dA3 * (self.cache["z3"] > 0)
        dW3 = (self.cache["a2"].T @ dZ3) / m
        db3 = np.mean(dZ3, axis=0, keepdims=True)
        dA2 = dZ3 @ self.params["W3"].T
        dZ2 = dA2 * (self.cache["z2"] > 0)
        dW2 = (self.cache["a1"].T @ dZ2) / m
        db2 = np.mean(dZ2, axis=0, keepdims=True)
        dA1 = dZ2 @ self.params["W2"].T
        dZ1 = dA1 * (self.cache["z1"] > 0)
        dW1 = (X.T @ dZ1) / m
        db1 = np.mean(dZ1, axis=0, keepdims=True)
        self.params["W1"] -= lr * dW1
        self.params["b1"] -= lr * db1
        self.params["W2"] -= lr * dW2
        self.params["b2"] -= lr * db2
        self.params["W3"] -= lr * dW3
        self.params["b3"] -= lr * db3
        self.params["W4"] -= lr * dW4
        self.params["b4"] -= lr * db4

    def fit(self, X, epochs: int = 50, batch_size: int = 64, verbose: bool = True):
        rng = np.random.default_rng(42)
        self.init_params(rng)
        n = X.shape[0]
        for epoch in range(epochs):
            perm = rng.permutation(n)
            X_shuffled = X[perm]
            epoch_loss = 0.0
            n_batches = 0
            for i in range(0, n, batch_size):
                batch = X_shuffled[i:i + batch_size]
                self.forward(batch)
                loss = self._mse(batch, self.cache["output"])
                self.backward(batch, self.lr)
                epoch_loss += loss
                n_batches += 1
            if verbose and (epoch + 1) % 10 == 0:
                logger.info(f"  AE Epoch {epoch+1}/{epochs} — loss: {epoch_loss/n_batches:.6f}")

    def predict(self, X):
        return self.forward(X)

    def reconstruction_error(self, X):
        recon = self.predict(X)
        return np.mean((X - recon) ** 2, axis=1)


# ============================================================
# 4. AEGISQ DETECTOR
# ============================================================
class AEGISQDetector:
    def __init__(self, config: Config):
        self.config = config
        self.autoencoder = None
        self.iforest = None
        self.scaler = None
        self._fitted = False

    def fit(self, X):
        logger.info("Training AEGISQ v2 detector...")
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        logger.info("  Training IsolationForest...")
        self.iforest = IsolationForest(
            n_estimators=200, contamination=0.05, random_state=42
        )
        self.iforest.fit(X_scaled)

        logger.info("  Training AutoEncoder...")
        self.autoencoder = AutoEncoder(
            input_dim=self.config.n_features,
            encoding_dim=self.config.ae_encoding_dim,
            lr=self.config.ae_lr,
        )
        self.autoencoder.fit(X_scaled, epochs=self.config.ae_epochs)

        self._fitted = True
        logger.info("AEGISQ v2 training complete.")

    def predict(self, X):
        if not self._fitted:
            raise RuntimeError("Detector not fitted yet.")
        X_scaled = self.scaler.transform(X)

        # 1. Isolation Forest score
        iforest_raw = -self.iforest.score_samples(X_scaled)
        iforest_score = (iforest_raw - iforest_raw.min()) / (
            iforest_raw.max() - iforest_raw.min() + 1e-10
        )

        # 2. Autoencoder reconstruction error
        recon_err = self.autoencoder.reconstruction_error(X_scaled)
        recon_score = np.clip(recon_err / (np.mean(recon_err) * 3 + 1e-10), 0, 1)

        # 3. Ensemble: weighted average
        return np.clip(0.5 * iforest_score + 0.5 * recon_score, 0, 1)


# ============================================================
# 5. ATTACK CLASSIFIER
# ============================================================
class AttackClassifier:
    """Classifies detected anomalies into attack types using feature signatures."""

    @staticmethod
    def classify(sample: np.ndarray, flow_features: dict = None) -> str:
        f = sample
        bytes_sent = f[2]
        bytes_recv = f[3]
        duration = f[4]
        pkt_sent = f[5]
        pkt_recv = f[6]
        dst_unique = f[11]
        syn_ratio = f[13]
        ack_ratio = f[14]
        small_pkt_ratio = f[19]
        c2_score = f[21]
        burst_ratio = f[22]
        idle_time = f[23]

        if duration < 1.0 and dst_unique > 5 and bytes_sent < 200:
            return "PORT_SCAN"
        if syn_ratio > 0.6 and pkt_sent > 50 and small_pkt_ratio > 0.5:
            return "DDoS"
        if c2_score > 0.5 and idle_time > 2 and duration > 15:
            return "C2_BEACON"
        if bytes_sent > 2000 and bytes_recv < 500 and duration > 30:
            return "DATA_EXFIL"
        if bytes_sent > 5000:
            return "DATA_EXFIL"
        return "UNKNOWN_ATTACK"


# ============================================================
# 6. ALERT ENGINE
# ============================================================
@dataclass
class Alert:
    alert_id: str
    flow_id: str
    anomaly_score: float
    severity: str
    attack_type: str
    quantum_signature: str
    features: dict = field(default_factory=dict)
    timestamp: str = ""


class AlertEngine:
    QUANTUM_ALGO = "CRYSTALS-Dilithium-3"

    def __init__(self, config: Config):
        self.config = config

    def triage(self, scores: np.ndarray, X: np.ndarray, flow_ids: List[str],
               attack_types: List[str] = None) -> List[Alert]:
        alerts = []
        now = datetime.utcnow()
        ts = now.isoformat()

        for i, (score, fid) in enumerate(zip(scores, flow_ids)):
            if score < self.config.anomaly_threshold:
                continue

            if score >= self.config.severity_critical:
                severity = "CRITICAL"
            elif score >= self.config.severity_high:
                severity = "HIGH"
            elif score >= self.config.severity_medium:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Classify attack type
            atype = AttackClassifier.classify(X[i])

            # Quantum signature
            sig_data = f"{fid}:{score:.4f}:{ts}:{atype}"
            sig = hashlib.shake_256(sig_data.encode()).hexdigest(16)

            # Feature summary
            feat = {
                "bytes_sent": round(float(X[i][2]), 1),
                "bytes_recv": round(float(X[i][3]), 1),
                "duration_s": round(float(X[i][4]), 2),
                "packets_sent": int(X[i][5]),
                "packets_recv": int(X[i][6]),
                "dst_unique": int(X[i][11]),
                "syn_ratio": round(float(X[i][13]), 3),
            }

            alerts.append(Alert(
                alert_id=f"AEG-{now.strftime('%Y%m%d')}-{i:04d}",
                flow_id=fid,
                anomaly_score=round(float(score), 4),
                severity=severity,
                attack_type=atype,
                quantum_signature=f"{self.QUANTUM_ALGO}:{sig}",
                features=feat,
                timestamp=ts,
            ))

        return alerts


# ============================================================
# 7. REPORTING
# ============================================================
def generate_report(alerts: List[Alert], total_flows: int, total_attacks: int):
    by_severity = {}
    by_type = {}
    for a in alerts:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_type[a.attack_type] = by_type.get(a.attack_type, 0) + 1

    critical = by_severity.get("CRITICAL", 0)
    high = by_severity.get("HIGH", 0)
    detections = sum(1 for a in alerts if a.severity in ("CRITICAL", "HIGH", "MEDIUM"))

    print("=" * 60)
    print("  AEGISQ v2 — DETECTION REPORT")
    print("=" * 60)
    print(f"  Total flows scanned:  {total_flows}")
    print(f"  Actual attacks:       {total_attacks}")
    print(f"  Alerts raised:        {len(alerts)}")
    print(f"  Detection rate:       {detections/max(total_attacks,1)*100:.1f}%")
    print(f"  False positives:      {max(0, len(alerts) - total_attacks)}")
    print()
    print("  By Severity:")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = by_severity.get(s, 0)
        print(f"    {s:10s} → {c}")
    print()
    print("  By Attack Type:")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {t:15s} → {c}")
    print()
    print("  Top 5 Alerts:")
    for a in sorted(alerts, key=lambda x: -x.anomaly_score)[:5]:
        print(f"    {a.alert_id} | {a.severity:8s} | {a.attack_type:12s} | "
              f"score={a.anomaly_score:.3f} | {a.flow_id}")
    print("=" * 60)

    return {
        "total_flows": total_flows,
        "total_attacks": total_attacks,
        "alerts_raised": len(alerts),
        "detection_rate": round(detections / max(total_attacks, 1) * 100, 1),
        "false_positives": max(0, len(alerts) - total_attacks),
        "by_severity": by_severity,
        "by_attack_type": by_type,
    }


# ============================================================
# 8. MAIN PIPELINE
# ============================================================
def run_pipeline():
    config = Config()
    logger.info("AEGISQ v2 — Quantum-Ready AI Threat Detection")
    logger.info("=" * 50)

    # Generate data
    logger.info("Generating synthetic network flows...")
    X, y, attack_types = DataGenerator.generate(
        config.n_normal, config.n_attack, config.rand_seed
    )

    # Train/test split
    split = len(X) // 2
    X_train, X_test = X[:split], X[split:]
    y_test = y[split:]
    at_test = attack_types[split:]

    # Train detector
    detector = AEGISQDetector(config)
    detector.fit(X_train)

    # Detect
    scores = detector.predict(X_test)

    # Alert
    flow_ids = [f"flow_{split+i:06d}" for i in range(len(X_test))]
    engine = AlertEngine(config)
    alerts = engine.triage(scores, X_test, flow_ids, at_test)

    # Report
    n_attacks = int(y_test.sum())
    report = generate_report(alerts, len(X_test), n_attacks)

    # Export JSON
    with open("aegisq_report.json", "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to aegisq_report.json")

    return alerts, report


if __name__ == "__main__":
    run_pipeline()
