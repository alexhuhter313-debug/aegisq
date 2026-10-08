"""
NexusProbe — AI-Guided Attack Surface Mapper

Correlates recon data into a scored attack graph, ranks entry points
by exploitability, and generates a prioritized assault plan for
authorized engagements.
"""

from __future__ import annotations

import asyncio
import json
import math
import socket
from typing import Any

from shadow313.core.kernel import KernelContext, register_command
from shadow313.tools.base import BaseTool, ToolResult

# ── Attack surface scoring weights ────────────────────────────────────────
SURFACE_WEIGHTS = {
    "http": 0.6, "https": 0.5, "ssh": 0.7, "ftp": 0.9,
    "telnet": 1.0, "rdp": 0.95, "smb": 0.95, "mysql": 0.85,
    "postgresql": 0.80, "mongodb": 0.85, "redis": 0.90,
    "elasticsearch": 0.90, "vnc": 0.95, "unknown": 0.5,
}

TECH_RISK = {
    "wordpress": 1.4, "drupal": 1.3, "joomla": 1.3, "php": 1.2,
    "apache": 1.1, "nginx": 1.0, "iis": 1.2, "express": 1.0,
    "django": 0.9, "cloudflare": 0.7,
}


class NexusProbe(BaseTool):
    """AI-Guided Attack Surface Mapper with scored entry point ranking."""

    TOOL_NAME = "nexusprobe"
    TEAM = "redteam"
    DESCRIPTION = "AI-guided attack surface mapper with scored entry point ranking"

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        result = ToolResult(tool_name=self.TOOL_NAME, target=target)
        self.output.section("NEXUSPROBE", f"Attack Surface Mapping — {target}")

        recon_data = kwargs.get("recon_data") or self.session.read("recon.json") or {}
        if not recon_data:
            self.output.warning("No recon data found. Running basic probe...")
            recon_data = await self._basic_probe(target)

        self.output.info("Building attack surface graph...")
        nodes = self._build_attack_nodes(target, recon_data)
        self.output.success(f"Identified {len(nodes)} attack surface nodes")

        self.output.info("Scoring entry points...")
        scored_nodes = self._score_nodes(nodes, recon_data)
        scored_nodes.sort(key=lambda n: n["attack_score"], reverse=True)

        attack_graph = self._build_attack_graph(scored_nodes, recon_data)
        critical_paths = self._find_critical_paths(attack_graph, scored_nodes)

        for node in scored_nodes[:10]:
            sev = self._score_to_severity(node["attack_score"])
            result.findings.append(self._finding(
                title=f"Attack Entry Point: {node['service']} on {node['host']}:{node['port']}",
                severity=sev,
                description=(
                    f"Service {node['service']} on port {node['port']} presents an "
                    f"attack surface score of {node['attack_score']:.2f}/10. "
                    f"Risk factors: {', '.join(node['risk_factors'])}"
                ),
                data=node,
                remediation=node.get("remediation", "Restrict access or apply service hardening"),
                mitre_technique=node.get("mitre_technique", "T1046"),
            ))

        result.data = {
            "target": target,
            "total_nodes": len(nodes),
            "scored_nodes": scored_nodes,
            "attack_graph": attack_graph,
            "critical_paths": critical_paths,
            "top_entry_point": scored_nodes[0] if scored_nodes else None,
            "surface_score": self._calculate_total_surface_score(scored_nodes),
        }

        self._display_results(result)
        return result

    def ai_context(self, result: ToolResult) -> str:
        top_nodes = result.data.get("scored_nodes", [])[:5]
        return f"""
You are analyzing an attack surface map for an authorized penetration test.

Target: {result.target}
Total Attack Nodes: {result.data.get('total_nodes', 0)}
Overall Surface Score: {result.data.get('surface_score', 0):.2f}/10

Top 5 Entry Points:
{json.dumps(top_nodes, indent=2, default=str)[:3000]}

Critical Attack Paths:
{json.dumps(result.data.get('critical_paths', []), indent=2, default=str)[:1000]}

Provide:
1. Executive Risk Summary
2. Top 3 Attack Vectors with MITRE ATT&CK mapping
3. Recommended First Strike
4. Quick Wins
5. Defensive Blind Spots
""".strip()

    async def _basic_probe(self, target: str) -> dict[str, Any]:
        from shadow313.recon.module import _port_scan, _web_fingerprint, COMMON_PORTS
        ports = await _port_scan(target, COMMON_PORTS[:20], timeout=0.5)
        web = await _web_fingerprint(target)
        return {"target": target, "ports": ports, "web": web, "dns": {}, "subdomains": []}

    def _build_attack_nodes(self, target: str, recon_data: dict) -> list[dict]:
        nodes = []
        for port_info in recon_data.get("ports", []):
            if port_info.get("state") != "open":
                continue
            nodes.append({
                "host": target, "port": port_info["port"],
                "service": port_info.get("service", "unknown"),
                "banner": port_info.get("banner", ""),
                "node_type": "service", "risk_factors": [], "attack_score": 0.0,
            })

        web = recon_data.get("web", {})
        if web.get("status_code"):
            for tech in web.get("technologies", []):
                nodes.append({
                    "host": target, "port": 443 if web.get("https") else 80,
                    "service": tech, "banner": web.get("server", ""),
                    "node_type": "technology", "risk_factors": [], "attack_score": 0.0,
                    "url": web.get("url", ""),
                })

        for sub in recon_data.get("subdomains", [])[:20]:
            nodes.append({
                "host": sub, "port": 443, "service": "https", "banner": "",
                "node_type": "subdomain", "risk_factors": ["subdomain_exposure"],
                "attack_score": 0.0,
            })
        return nodes

    def _score_nodes(self, nodes: list[dict], recon_data: dict) -> list[dict]:
        technologies = recon_data.get("web", {}).get("technologies", [])
        tech_multiplier = max(
            (TECH_RISK.get(t.lower(), 1.0) for t in technologies), default=1.0
        )

        for node in nodes:
            service = node["service"].lower()
            base_score = SURFACE_WEIGHTS.get(service, 0.5) * 10
            score = base_score * tech_multiplier
            risk_factors = list(node.get("risk_factors", []))

            if service in ("telnet", "ftp"):
                risk_factors.append("cleartext_protocol")
                score *= 1.3
            if service in ("rdp", "vnc"):
                risk_factors.append("remote_desktop_exposure")
                score *= 1.2
            if service in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch"):
                risk_factors.append("database_exposed")
                score *= 1.4
            if node.get("banner") and any(v in node["banner"].lower() for v in ["1.", "2.", "3."]):
                risk_factors.append("version_disclosure")
                score *= 1.1
            if node["node_type"] == "subdomain":
                risk_factors.append("expanded_attack_surface")

            node["attack_score"] = min(10.0, round(score, 2))
            node["risk_factors"] = list(set(risk_factors))
            node["mitre_technique"] = self._map_to_mitre(service)
            node["remediation"] = self._get_remediation(service)
        return nodes

    def _build_attack_graph(self, nodes: list[dict], recon_data: dict) -> dict:
        graph = {"nodes": [{"id": "internet", "type": "source", "label": "Internet"}], "edges": []}
        for i, node in enumerate(nodes[:15]):
            node_id = f"node_{i}"
            graph["nodes"].append({
                "id": node_id, "type": node["node_type"],
                "label": f"{node['service']}:{node['port']}",
                "score": node["attack_score"], "host": node["host"],
            })
            graph["edges"].append({"from": "internet", "to": node_id, "weight": node["attack_score"]})

        high_score = [n for n in nodes if n["attack_score"] >= 7.0]
        for i, node in enumerate(high_score[:5]):
            graph["edges"].append({
                "from": f"node_{nodes.index(node)}", "to": "internal_network",
                "weight": node["attack_score"] * 0.8, "label": "lateral_movement",
            })
        if high_score:
            graph["nodes"].append({"id": "internal_network", "type": "target", "label": "Internal Network"})
        return graph

    def _find_critical_paths(self, graph: dict, nodes: list[dict]) -> list[dict]:
        paths = []
        high_risk = [n for n in nodes if n["attack_score"] >= 7.0]
        for node in high_risk[:3]:
            paths.append({
                "path": ["Internet", f"{node['service']}:{node['port']}", "Internal Network"],
                "score": node["attack_score"], "technique": node.get("mitre_technique", ""),
                "description": f"Direct exploitation of {node['service']} on port {node['port']} could provide initial access with score {node['attack_score']:.1f}/10",
            })
        return paths

    def _calculate_total_surface_score(self, nodes: list[dict]) -> float:
        if not nodes:
            return 0.0
        scores = [n["attack_score"] for n in nodes]
        weights = [1 / (i + 1) for i in range(len(scores))]
        weighted = sum(s * w for s, w in zip(scores, weights))
        return round(min(10.0, weighted / sum(weights)), 2)

    def _map_to_mitre(self, service: str) -> str:
        mapping = {
            "ssh": "T1021.004", "rdp": "T1021.001", "smb": "T1021.002",
            "ftp": "T1021.003", "http": "T1190", "https": "T1190",
            "mysql": "T1190", "redis": "T1190", "mongodb": "T1190",
            "telnet": "T1021", "vnc": "T1021.005",
        }
        return mapping.get(service.lower(), "T1046")

    def _get_remediation(self, service: str) -> str:
        remediations = {
            "telnet": "Disable Telnet immediately — use SSH instead",
            "ftp": "Replace FTP with SFTP/FTPS or disable entirely",
            "rdp": "Restrict RDP to VPN only, enable NLA, use MFA",
            "smb": "Disable SMBv1, restrict to internal networks only",
            "redis": "Bind to localhost only, enable AUTH, disable dangerous commands",
            "mongodb": "Enable authentication, bind to localhost, use TLS",
            "elasticsearch": "Enable X-Pack security, bind to localhost",
            "vnc": "Disable VNC or restrict to VPN, use strong password",
        }
        return remediations.get(service.lower(), f"Apply service hardening for {service}")

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 5.0: return "MEDIUM"
        return "LOW"

    def _display_results(self, result: ToolResult) -> None:
        surface_score = result.data.get("surface_score", 0)
        nodes = result.data.get("scored_nodes", [])
        self.output.kv_table({
            "Target": result.target,
            "Attack Nodes": str(len(nodes)),
            "Surface Score": f"{surface_score:.1f}/10",
            "Critical Paths": str(len(result.data.get("critical_paths", []))),
            "Top Entry Point": f"{nodes[0]['service']}:{nodes[0]['port']} (score: {nodes[0]['attack_score']:.1f})" if nodes else "none",
        }, title="NexusProbe — Attack Surface Map")

        self.output.section("Ranked Entry Points")
        for node in nodes[:8]:
            sev = self._score_to_severity(node["attack_score"])
            self.output.info(
                f"  {self.output.severity_badge(sev)}  "
                f"{node['host']}:{node['port']:<6} {node['service']:<15} "
                f"score={node['attack_score']:.1f}  "
                f"[{', '.join(node['risk_factors'][:2])}]"
            )


@register_command("tools", "nexusprobe")
async def run_nexusprobe(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """NexusProbe — AI-guided attack surface mapper."""
    target = kwargs.get("target", "")
    if not target:
        ctx.output.error("No target specified")
        return {}
    tool = NexusProbe(ctx)
    result = await tool.run_with_ai(target, **kwargs)
    return result.to_dict()
