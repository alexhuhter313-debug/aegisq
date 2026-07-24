# AEGISQ — Quantum-Ready Threat Defense Platform

**AI-Powered XDR/SOC Automation with Post-Quantum Cryptography**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

AEGISQ is a next-generation security platform combining:
- **AI Threat Detection** — ML-powered anomaly detection and automated triage
- **Post-Quantum Cryptography** — Quantum-safe encryption for future-proof security
- **Zero-Trust Architecture** — Continuous verification, least-privilege access
- **Quantum-Safe AI Copilot** — AI assistant for security operations

## Features

### Detection Plane
- Real-time threat detection using ensemble ML models
- Automated alert triage and prioritization
- Integration with existing SIEM/SOC tools

### Response Plane
- Automated incident response workflows
- Playbook execution engine
- Integration with ticketing systems

### Trust Plane
- Post-quantum cryptographic algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium)
- Zero-trust network architecture
- Continuous authentication and authorization

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGISQ PLATFORM                          │
├─────────────────────────────────────────────────────────────┤
│  Detection Plane  │  Response Plane  │  Trust Plane         │
│  ├─ ML Models     │  ├─ Playbooks    │  ├─ PQC Crypto       │
│  ├─ Anomaly Det.  │  ├─ Automation   │  ├─ Zero-Trust       │
│  └─ Alert Triage  │  └─ Integration  │  └─ AI Copilot       │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install
pip install aegisq

# Run detection
aegisq detect --input logs.json

# Generate quantum-safe keys
aegisq crypto --generate-keys

# Start AI copilot
aegisq copilot --interactive
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| ML Framework | scikit-learn, PyTorch |
| PQC Library | liboqs-python |
| Database | PostgreSQL + TimescaleDB |
| Message Queue | Redis Streams |
| API | FastAPI |

## License

MIT © 2026 AEGISQ
