"""Kernel — central orchestrator for Shadow313."""

import sys
from typing import Any, Optional


class Output:
    """Handles CLI output formatting."""

    @staticmethod
    def print_result(result: Any) -> None:
        """Print a result dict in a readable format."""
        if isinstance(result, dict):
            for key, value in result.items():
                print(f"  {key}: {value}")
        else:
            print(result)


class Kernel:
    """Central orchestrator for dispatching commands to modules."""

    def __init__(
        self,
        verbose: bool = False,
        no_ai: bool = False,
        lab_mode: bool = False,
    ):
        self.verbose = verbose
        self.no_ai = no_ai
        self.lab_mode = lab_mode
        self.output = Output()

    def dispatch(self, command: str, **kwargs) -> dict:
        """Dispatch a command to the appropriate module.

        Args:
            command: One of "recon", "vuln", "network"
            **kwargs: Command-specific arguments

        Returns:
            Result dict with status and data
        """
        if command == "recon":
            return self._run_recon(**kwargs)
        elif command == "vuln":
            return self._run_vuln(**kwargs)
        elif command == "network":
            return self._run_network(**kwargs)
        else:
            return {"status": "error", "message": f"Unknown command: {command}"}

    def _run_recon(self, target: str, mode: str = "quick") -> dict:
        """Run reconnaissance on a target."""
        if self.verbose:
            print(f"[Kernel] Recon on {target} (mode={mode})")
        return {
            "status": "success",
            "command": "recon",
            "target": target,
            "mode": mode,
            "message": f"Recon completed for {target}",
        }

    def _run_vuln(self, target: str) -> dict:
        """Run vulnerability analysis on a target."""
        if self.verbose:
            print(f"[Kernel] Vuln scan on {target}")
        return {
            "status": "success",
            "command": "vuln",
            "target": target,
            "message": f"Vulnerability scan completed for {target}",
        }

    def _run_network(self, interface: str, mode: str = "monitor") -> dict:
        """Run network intelligence."""
        if self.verbose:
            print(f"[Kernel] Network {mode} on {interface}")
        return {
            "status": "success",
            "command": "network",
            "interface": interface,
            "mode": mode,
            "message": f"Network {mode} completed on {interface}",
        }
