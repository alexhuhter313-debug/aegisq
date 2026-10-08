"""Full detection pipeline."""
import logging,numpy as np
from aegisq.config import DetectionConfig
from aegisq.detector.data_generator import DataGenerator
from aegisq.detector.engine import AEGISQDetector,AlertEngine
from aegisq.detector.reporter import generate_report
logging.basicConfig(level=logging.INFO,format="%(asctime)s | %(levelname)-8s | %(message)s")
logger=logging.getLogger("aegisq")
def run_pipeline(n_normal=5000,n_attack=200,threshold=0.3):
    config=DetectionConfig(n_normal=n_normal,n_attack=n_attack,anomaly_threshold=threshold)
    logger.info("AEGISQ v2 — Pipeline Start")
    X,y,at=DataGenerator.generate(config.n_normal,config.n_attack,config.rand_seed)
    split=len(X)//2;X_train,X_test=X[:split],X[split:];y_test,at_test=y[split:],at[split:]
    detector=AEGISQDetector(config).fit(X_train)
    scores=detector.predict(X_test)
    flow_ids=[f"flow_{split+i:06d}" for i in range(len(X_test))]
    alerts=AlertEngine(config).triage(scores,X_test,flow_ids,at_test)
    return alerts,generate_report(alerts,len(X_test),int(y_test.sum()))
