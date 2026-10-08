# AEGISQ — Quantum-Ready AI Threat Detection Platform

Ensemble ML detection (Autoencoder + Isolation Forest) + Fortress defense/offense suite + NexusProbe attack surface mapping.

## Structure
```
src/aegisq/
├── __init__.py          # Package init
├── cli.py               # CLI entry (aegisq detect/recon/vuln/...)
├── detection.py         # ML pipeline (21K-lines engine)
├── core/kernel.py       # Command dispatcher
├── modules/fortress/    # Offense/defense suite
└── tools/
    ├── base.py          # Finding/reporting base
    └── nexusprobe.py    # Attack surface mapper
```

## Quick Start
```bash
docker compose up -d
# or
pip install -e .
aegisq detect
```

## Commands: detect | recon | vuln | network | probe | fortress
