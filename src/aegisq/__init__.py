"""AEGISQ — Quantum-Ready AI Threat Detection Platform."""
__version__ = "2.1.0"
from aegisq.detection import AEGISQDetector, AlertEngine, DataGenerator, Config, run_pipeline
from aegisq.core.kernel import Kernel
from aegisq.cli import main
__all__ = ["Kernel", "AEGISQDetector", "AlertEngine", "DataGenerator", "Config", "run_pipeline", "main", "__version__"]
