"""Detection engine."""
import numpy as np, logging
from aegisq.config import DetectionConfig
from aegisq.detector.autoencoder import Autoencoder
logger=logging.getLogger("aegisq")
class AEGISQDetector:
    def __init__(self,config=None):self.config=config or DetectionConfig();self.model=Autoencoder(self.config.n_features,self.config.ae_encoding_dim,self.config.ae_lr)
    def fit(self,X):logger.info(f"Training ({X.shape[0]} samples)...");self.model.fit(X,epochs=self.config.ae_epochs);return self
    def predict(self,X):return self.model.anomaly_score(X)
class AlertEngine:
    def __init__(self,config=None):self.config=config or DetectionConfig()
    def triage(self,scores,X,flow_ids,attack_types):
        alerts=[]
        for i,s in enumerate(scores):
            if s<self.config.anomaly_threshold:continue
            at=attack_types[i] if i<len(attack_types) else "UNKNOWN"
            sev="CRITICAL" if s>=self.config.severity_critical else "HIGH" if s>=self.config.severity_high else "MEDIUM" if s>=self.config.severity_medium else "LOW"
            alerts.append({"flow_id":flow_ids[i],"anomaly_score":float(s),"severity":sev,"attack_type":at})
        return alerts
