# AEGISQ — Quantum-Ready Threat Defense

**AI-driven threat detection with quantum-safe architecture.**

AEGISQ combines ensemble ML (Isolation Forest + Autoencoder) with post-quantum cryptographic readiness for real-time threat detection.

## Architecture

```
src/aegisq/
├── __init__.py          # Package init
├── detection.py         # Ensemble anomaly detection pipeline
├── Dockerfile           # Container build
├── requirements.txt     # Python dependencies
└── docker-compose.yml   # Service orchestration
```

## Quick Start

```bash
docker compose up -d
```

## Features

- Ensemble Anomaly Detection (Isolation Forest + Autoencoder)
- Real-Time Feature Extraction
- Intelligent Alert Triage
- Quantum-Ready Architecture
