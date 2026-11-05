"""Unified CLI for AEGISQ."""
import argparse, sys
from aegisq import __version__

def main():
    p = argparse.ArgumentParser(prog="aegisq")
    p.add_argument("--version", action="version", version=f"aegisq {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    s = p.add_subparsers(dest="command")
    sp = s.add_parser("serve", help="Start REST API server")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8000)
    sp = s.add_parser("pipeline", help="Run detection pipeline once")
    sp = s.add_parser("recon", help="Run NexusProbe recon")
    sp.add_argument("target", help="Target domain or IP")
    sp = s.add_parser("copilot", help="Query AI copilot")
    sp.add_argument("query", nargs="+", help="Your question")
    sp = s.add_parser("crypto", help="Generate post-quantum keys")
    sp.add_argument("--algorithm", default="dilithium", choices=["dilithium", "kyber", "sphincs"])
    args = p.parse_args()
    if not args.command:
        p.print_help()
        return
    if args.command == "serve":
        from aegisq.api import serve
        serve()
    elif args.command == "pipeline":
        from aegisq.detector.pipeline import run_pipeline
        report = run_pipeline()
        import json
        print(json.dumps(report, indent=2))
    elif args.command == "recon":
        from aegisq.nexus.probe import NexusProbe
        n = NexusProbe()
        results = n.scan(args.target)
        import json
        print(json.dumps(results, indent=2))
    elif args.command == "copilot":
        from aegisq.copilot.assistant import SecurityCopilot
        c = SecurityCopilot()
        result = c.analyze(" ".join(args.query))
        print(f"[{result.confidence:.0%} confidence]")
        print(result.response)
    elif args.command == "crypto":
        from aegisq.crypto.pqc import PQCProvider
        pqc = PQCProvider()
        keys = pqc.generate_keypair(args.algorithm)
        print(f"Algorithm: {args.algorithm}")
        print(f"Public key: {keys.public_key.hex()[:64]}...")
        print(f"Key ID: {keys.key_id}")

if __name__ == "__main__":
    main()
