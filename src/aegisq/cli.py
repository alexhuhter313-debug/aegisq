"""AEGISQ CLI."""
import argparse, sys, json, asyncio
from aegisq import __version__
from aegisq.core.kernel import Kernel
def main():
    p = argparse.ArgumentParser(prog="aegisq")
    p.add_argument("--version", action="version", version=f"aegisq {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-ai", action="store_true")
    p.add_argument("--lab-mode", action="store_true")
    sub = p.add_subparsers(dest="command")
    rp = sub.add_parser("recon"); rp.add_argument("-t","--target", required=True)
    rp.add_argument("--mode", choices=["quick","full","passive"], default="quick")
    vp = sub.add_parser("vuln"); vp.add_argument("-t","--target", required=True)
    np = sub.add_parser("network"); np.add_argument("-i","--interface")
    np.add_argument("--mode", choices=["monitor","analyze","forensics"], default="monitor")
    dp = sub.add_parser("detect")
    dp.add_argument("--threshold", type=float, default=0.3)
    dp.add_argument("-o","--output", default="aegisq_report.json")
    pp = sub.add_parser("probe"); pp.add_argument("-t","--target", required=True)
    fp = sub.add_parser("fortress"); fp.add_argument("action", choices=["tarpit","status","sweep"])
    args = p.parse_args()
    if not args.command: p.print_help(); sys.exit(0)
    kernel = Kernel(verbose=args.verbose, no_ai=args.no_ai, lab_mode=args.lab_mode)
    if args.command == "detect":
        from aegisq.detection import Config as DC, run_pipeline
        DC.n_attack, DC.n_normal = 200, 5000
        DC.anomaly_threshold = args.threshold
        alerts, report = run_pipeline()
        with open(args.output, "w") as f: json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")
    elif args.command == "probe":
        from aegisq.tools.nexusprobe import NexusProbe
        probe = NexusProbe(); r = asyncio.run(probe.run(args.target))
        print(r)
    else:
        kwa = {"target": args.target} if hasattr(args,"target") else {}
        kwa.update({"mode": args.mode} if hasattr(args,"mode") and args.mode else {})
        kwa.update({"action": args.action} if hasattr(args,"action") else {})
        kwa.update({"interface": args.interface} if hasattr(args,"interface") and args.interface else {})
        result = kernel.dispatch(args.command, **kwa)
        kernel.output.print_result(result)
