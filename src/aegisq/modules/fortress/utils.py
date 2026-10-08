"""Fortress Utilities — Common security utilities."""

import hashlib
import os
import secrets
from typing import Any


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure token."""
    return secrets.token_urlsafe(length)


def hash_password(password: str, salt: str = None) -> dict:
    """Hash a password with salt using SHA-256."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return {"hash": hashed, "salt": salt}


def verify_password(password: str, hash_dict: dict) -> bool:
    """Verify a password against a hash."""
    salt = hash_dict["salt"]
    expected_hash = hash_dict["hash"]
    actual = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return actual == expected_hash


def sanitize_input(user_input: str) -> str:
    """Basic input sanitization."""
    # Remove potentially dangerous characters
    dangerous = [";", "&&", "||", "`", "$", "(", ")", "{", "}", "<", ">"]
    sanitized = user_input
    for char in dangerous:
        sanitized = sanitized.replace(char, "")
    return sanitized.strip()


def generate_report(findings: list[dict], title: str = "Security Report") -> str:
    """Generate a simple text report from findings."""
    report = [f"# {title}", ""]

    for i, finding in enumerate(findings, 1):
        report.append(f"## Finding {i}: {finding.get('title', 'Untitled')}")
        report.append(f"**Severity:** {finding.get('severity', 'UNKNOWN')}")
        report.append(f"**Description:** {finding.get('description', 'No description')}")
        if finding.get('remediation'):
            report.append(f"**Remediation:** {finding['remediation']}")
        report.append("")

    return "\n".join(report)


if __name__ == "__main__":
    # Demo
    print("[+] Fortress Utilities Demo")

    token = generate_secure_token()
    print(f"[*] Secure token: {token}")

    password_hash = hash_password("test123")
    print(f"[*] Password hash: {password_hash}")

    verified = verify_password("test123", password_hash)
    print(f"[*] Password verified: {verified}")

    sanitized = sanitize_input("test; rm -rf /")
    print(f"[*] Sanitized input: {sanitized}")
