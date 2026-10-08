# AEGISQ v2 — Quantum-Ready AI Threat Detection

AI-powered XDR/SOC automation.

## Quick Start
```
aegisq pipeline
aegisq serve
aegisq recon -t example.com
aegisq nexus -t example.com
```

## Services
| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | REST detection endpoint |
| Detector | — | Batch pipeline |

## Stack
- Detector: NumPy autoencoder
- Fortress: Offense/defense suite
- NexusProbe: Attack surface mapper
- API: FastAPI
