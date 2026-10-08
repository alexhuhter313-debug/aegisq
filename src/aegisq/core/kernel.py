"""Kernel orchestrator."""
class Output:
    @staticmethod
    def print_result(r):
        if isinstance(r,dict):
            for k,v in r.items(): print(f"  {k}: {v}")
        else: print(r)
class Kernel:
    def __init__(self, verbose=False, no_ai=False, lab_mode=False):
        self.verbose, self.no_ai, self.lab_mode = verbose, no_ai, lab_mode
        self.output = Output()
    def dispatch(self, cmd, **kw):
        m = {"recon": self._recon, "vuln": self._vuln, "network": self._net, "fortress": self._fort}
        return m.get(cmd, lambda **_: {"status":"error","message":f"Unknown: {cmd}"})(**kw)
    def _recon(self, target="", mode="quick", **kw):
        return {"status":"success","command":"recon","target":target,"mode":mode} if not self.verbose else {"status":"success","command":"recon","target":target,"mode":mode}
    def _vuln(self, target="", **kw):
        return {"status":"success","command":"vuln","target":target}
    def _net(self, interface="", mode="monitor", **kw):
        return {"status":"success","command":"network","interface":interface,"mode":mode}
    def _fort(self, action="status", **kw):
        return {"status":"success","command":"fortress","action":action}
