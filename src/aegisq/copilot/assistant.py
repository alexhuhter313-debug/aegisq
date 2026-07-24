"""AI Copilot Module — Security operations assistant."""

from typing import Any
from dataclasses import dataclass


@dataclass
class CopilotResponse:
    """Response from the AI copilot."""
    query: str
    response: str
    confidence: float
    sources: list[str]


class SecurityCopilot:
    """AI-powered security operations assistant."""

    def __init__(self, model: str = "local"):
        self.model = model
        self.context: list[dict] = []

    def query(self, question: str, context: dict = None) -> CopilotResponse:
        """Query the copilot with a security question."""
        # Simplified demo implementation
        # In production, use Ollama or OpenAI-compatible API

        response_text = self._generate_response(question, context)
        confidence = self._calculate_confidence(question, context)
        sources = self._get_sources(question)

        return CopilotResponse(
            query=question,
            response=response_text,
            confidence=confidence,
            sources=sources,
        )

    def _generate_response(self, question: str, context: dict = None) -> str:
        """Generate a response to the question."""
        question_lower = question.lower()

        if "threat" in question_lower or "attack" in question_lower:
            return "Based on current threat intelligence, I recommend checking for indicators of compromise in your network logs. Focus on unusual outbound connections and privilege escalation attempts."
        elif "vulnerability" in question_lower or "cve" in question_lower:
            return "I've analyzed the vulnerability landscape. Critical vulnerabilities to patch immediately include those in exposed services with CVSS > 9.0. Run a vulnerability scan to identify affected systems."
        elif "incident" in question_lower:
            return "For incident response, follow the NIST framework: Preparation, Detection & Analysis, Containment, Eradication, Recovery, and Post-Incident Activity. I can help you create a playbook."
        else:
            return "I can help with threat detection, vulnerability management, incident response, and security operations. What specific area would you like to explore?"

    def _calculate_confidence(self, question: str, context: dict = None) -> float:
        """Calculate confidence in the response."""
        # Simplified confidence calculation
        base_confidence = 0.7
        if context:
            base_confidence += 0.1
        if len(question) > 20:
            base_confidence += 0.1
        return min(1.0, base_confidence)

    def _get_sources(self, question: str) -> list[str]:
        """Get sources for the response."""
        return [
            "NIST Cybersecurity Framework",
            "MITRE ATT&CK",
            "CISA Known Exploited Vulnerabilities",
        ]

    def add_context(self, context: dict):
        """Add context to the copilot's memory."""
        self.context.append(context)

    def clear_context(self):
        """Clear the copilot's context."""
        self.context.clear()


if __name__ == "__main__":
    print("[+] AEGISQ Security Copilot Demo")

    copilot = SecurityCopilot()

    # Test queries
    queries = [
        "What are the latest threats?",
        "How do I handle a ransomware incident?",
        "Which vulnerabilities should I patch first?",
    ]

    for query in queries:
        response = copilot.query(query)
        print(f"\n[*] Query: {query}")
        print(f"    Response: {response.response}")
        print(f"    Confidence: {response.confidence:.2f}")
