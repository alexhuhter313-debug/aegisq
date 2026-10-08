"""Unified CLI."""
import argparse,sys; from aegisq import __version__
def main():
    p = argparse.ArgumentParser(prog="aegisq")
    p.add_argument("--version",action="version",version=f"aegisq {__version__}")
    p.add_argument("-v","--verbose",action="store_true")
    s = p.add_subparsers(dest="command")
    for cmd,help_text in [("pipeline","Detection pipeline"),("recon","Reconnaissance"),("vuln","Vulnerability analysis"),("network","Network intelligence"),("serve","REST API server"),("nexus","Attack surface mapping")]:
        sp = s.add_parser(cmd,help=help_text)
        if cmd in ("recon","vuln","nexus"): sp.add_argument("-t","--target",required=True)
        if cmd=="recon": sp.add_argument("--mode",choices=["quick","full","passive"],default="quick")
        if cmd=="network": sp.add_argument("-i","--interface"); sp.add_argument("--mode",choices=["monitor","analyze","forensics"],default="monitor")
        if cmd=="pipeline": sp.add_argument("--normal",type=int,default=5000); sp.add_argument("--attack",type=int,default=200); sp.add_argument("--threshold",type=float,default=0.3)
    a = p.parse_args()
    if not a.command: p.print_help(); sys.exit(0)
    if a.command=="pipeline": from aegisq.detector.pipeline import run_pipeline; run_pipeline(n_normal=a.normal,n_attack=a.attack,threshold=a.threshold)
    elif a.command=="serve": from aegisq.api import serve; serve()
    elif a.command=="nexus": from aegisq.nexus.probe import run_nexusprobe; import asyncio; asyncio.run(run_nexusprobe(a.target))
    else: from aegisq.kernel import Kernel; k=Kernel(verbose=a.verbose); kw={k:v for k,v in vars(a).items() if v and k!="command"}; print(k.dispatch(a.command,**kw))
if __name__=="__main__": main()
