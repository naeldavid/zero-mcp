"""SSL/TLS config check wrapper for MCP server.

Wraps: sslscan or testssl.sh (whichever is installed on the system)
Policy: target required; only allowlisted extra flags may be layered on top.
Timeout: 120s (aggressive on Pi Zero to prevent OOM).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, List

# Determine which binary is available: sslscan preferred, then testssl.sh
SSLSCAN_PATH = "/usr/bin/sslscan"
TESTSSL_PATH = "/usr/bin/testssl.sh"

_BINARY = None


def _get_binary() -> str:
    global _BINARY
    if _BINARY is not None:
        return _BINARY
    if os.path.isfile(SSLSCAN_PATH) and os.access(SSLSCAN_PATH, os.X_OK):
        _BINARY = SSLSCAN_PATH
    elif os.path.isfile(TESTSSL_PATH) and os.access(TESTSSL_PATH, os.X_OK):
        _BINARY = TESTSSL_PATH
    else:
        _BINARY = SSLSCAN_PATH  # fallback; wrapper will report binary not found
    return _BINARY


DEFAULTS: Dict[str, Any] = {
    "default_args": [],
    "max_output_kb": 64,
    "allowlisted_flags": {"-H", "-U", "-N", "-E", "-X", "-S", "-R", "-"},
}

DEFAULTS_SSL_TUNING = ""


async def run(target: str, extra_args: List[str] | None = None, cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Run an SSL/TLS configuration check and return structured JSON.

    Args:
        target: hostname or IP:port (required, e.g. example.com or example.com:443)
        extra_args: extra CLI flags; only those in the allowlist are permitted.
        cfg: optional runtime config overrides.

    Returns:
        dict with keys: tool, target, status, stdout, stderr, exit_code,
        truncated, key_findings, submitted_at (ISO-8601).
    """
    if not target or not target.strip():
        msg = "ssl: target is required"
        return _err(msg)

    if cfg:
        pass  # config-driven overrides handled at server level

    # Determine which binary to use
    binary = _get_binary()
    if not os.path.isfile(binary):
        return {
            "tool": "ssl",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": f"ssl: neither sslscan nor testssl.sh installed at {binary}",
            "exit_code": 127,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }

    args: List[str] = list(DEFAULTS["default_args"])

    # Apply allowlisted extra args
    if extra_args:
        allowed = DEFAULTS["allowlisted_flags"]
        filtered: List[str] = []
        for a in extra_args:
            if a in allowed:
                filtered.append(a)
            else:
                pass  # reject unknown flag silently
        args.extend(filtered)

    cmd: List[str] = [binary] + args + [target]

    timeout_sec = cfg.get("timeout_seconds", 120) if cfg else 120
    max_bytes = cfg.get("max_output_kb", 64) * 1024 if cfg else 64 * 1024

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "tool": "ssl",
                "target": target,
                "status": "timeout",
                "stdout": "",
                "stderr": "ssl scan timed out after " + str(timeout_sec) + "s",
                "exit_code": -1,
                "truncated": True,
                "key_findings": [],
                "submitted_at": _now_iso(),
            }

        exit_code = proc.returncode

        # Keep only the last max_bytes bytes
        if len(stdout) > max_bytes:
            stdout = stdout[-max_bytes:]
            truncated = True
        else:
            truncated = False

        if len(stderr) > max_bytes:
            stderr = stderr[-max_bytes:]

        # Parse key findings: extract TLS version, cipher, certificate info
        key_findings = _parse_ssl_output(stdout.decode(errors="replace"))

        return {
            "tool": "ssl",
            "target": target,
            "status": "done" if exit_code == 0 else "failed",
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
            "exit_code": exit_code,
            "truncated": truncated,
            "key_findings": key_findings,
            "submitted_at": _now_iso(),
        }

    except FileNotFoundError:
        return {
            "tool": "ssl",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": "ssl binary not found at " + str(binary),
            "exit_code": 127,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }
    except Exception as e:
        return {
            "tool": "ssl",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }


def _parse_ssl_output(output: str) -> List[str]:
    """Parse sslscan/testssl output to extract key TLS findings.

    Extracts: TLS version, cert issues, weak ciphers, supporting protocols.
    """
    findings: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        # TLS version
        if "tls 1.3" in low:
            findings.append("TLS 1.3 supported")
        elif "tls 1.2" in low:
            findings.append("TLS 1.2 supported")
        elif "ssl 3" in low or "sslv3" in low:
            findings.append("SSL 3.0 detected (deprecated)")
        # Weak ciphers
        if "weak" in low and "cipher" in low:
            findings.append("Weak cipher detected")
        # Certificate info
        if "subject:" in low or "issuer:" in low:
            findings.append("Certificate info present")
        # Protocol support
        if "http" in low and "ssl" in low:
            findings.append("HTTP over SSL supported")
        # Perfect forward secrecy
        if "pfs" in low or "forward secrecy" in low:
            findings.append("Perfect forward secrecy supported")
    # Deduplicate
    seen = set()
    deduped = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            deduped.append(f)
    return deduped[:15]


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _err(msg: str) -> Dict[str, Any]:
    return {
        "tool": "ssl",
        "target": "",
        "status": "failed",
        "stdout": "",
        "stderr": msg,
        "exit_code": -1,
        "truncated": False,
        "key_findings": [],
        "submitted_at": _now_iso(),
    }