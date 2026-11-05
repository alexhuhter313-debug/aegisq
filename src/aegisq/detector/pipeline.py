"""Full detection pipeline — standalone runner."""
import logging, numpy as np
from aegisq.config import DetectionConfig
from aegisq.detector.data_generator import DataGenerator
from aegisq.detector.engine import AEGISQDetector, AlertEngine
from aegisq.detector.reporter import generate_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("aegisq-pipeline")

def run_pipeline(config: DetectionConfig = None) -> dict:
    if config is None:
        config = DetectionConfig()
    logger.info("Generating traffic data...")
    X, y, _ = DataGenerator.generate(config.n_normal, config.n_attack)
    logger.info(f"Training detector on {len(X)} samples...")
    detector = AEGISQDetector(config).fit(X)
    logger.info("Running detection...")
    scores = detector.predict(X)
    alerts = AlertEngine.analyze(scores, y, config)
    report = generate_report(alerts, len(X), int(np.sum(y)))
    logger.info(f"Detection complete: {report['alerts_raised']} alerts, {report['detection_rate']}% rate")
    return report

if __name__ == "__main__":
    import json
    report = run_pipeline()
    print(json.dumps(report, indent=2))
