"""Base classes for Shadow313 tools."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """A security finding from a tool."""
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    data: dict = field(default_factory=dict)
    remediation: str = ""
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "data": self.data,
            "remediation": self.remediation,
            "mitre_technique": self.mitre_technique,
        }


@dataclass
class ToolResult:
    """Result from a tool execution."""
    tool_name: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
            "success": self.success,
            "error": self.error,
        }


class BaseTool:
    """Base class for all Shadow313 tools."""

    TOOL_NAME: str = "base"
    TEAM: str = "general"  # redteam, blueteam, general
    DESCRIPTION: str = ""

    def __init__(self, ctx=None):
        self.ctx = ctx
        self.output = ctx.output if ctx else DummyOutput()
        self.session = ctx.session if ctx else DummySession()

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        raise NotImplementedError

    async def run_with_ai(self, target: str, **kwargs: Any) -> ToolResult:
        """Run tool and optionally enrich with AI analysis."""
        result = await self.run(target, **kwargs)
        # AI enrichment would happen here if enabled
        return result

    def ai_context(self, result: ToolResult) -> str:
        """Return context string for AI analysis."""
        return ""

    def _finding(self, title: str, severity: str, description: str, **kwargs) -> Finding:
        return Finding(title=title, severity=severity, description=description, **kwargs)


class DummyOutput:
    """Dummy output handler for standalone use."""
    def section(self, *args, **kwargs): pass
    def info(self, msg): print(f"[*] {msg}")
    def success(self, msg): print(f"[+] {msg}")
    def warning(self, msg): print(f"[!] {msg}")
    def error(self, msg): print(f"[-] {msg}")
    def kv_table(self, data, title=""): print(f"\n{title}: {data}")
    def severity_badge(self, sev): return f"[{sev}]"


class DummySession:
    """Dummy session for standalone use."""
    def read(self, key): return {}
    def write(self, key, value): pass
