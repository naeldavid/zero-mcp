"""Nikto web vulnerability scanner wrapper for MCP server.

Wraps: nikto -Tuning 123b (info-gathering/misconfig checks only — no DoS tests)
Policy: target required; only a small allowlisted set of extra flags may be layered on top.
Note: nikto is CPU-intensive; on Pi Zero cap timeout aggressively and prefer
running from a more powerful box over Tailscale if scans time out.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, List

DEFAULTS: Dict[str, Any] = {
    "default_args": ["-Tuning", "123b"],
    "max_output_kb": 64,
    "allowlisted_flags": {"-Tuning", "-verbose", "-output", "-Format", "-Display"},
}

DEFAULTS_NIKTO_TUNING = "123b"


async def run(target: str, extra_args: List[str] | None = None, cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Run a nikto web vulnerability scan and return structured JSON.

    Args:
        target: target URL (required, e.g. http://example.com/)
        extra_args: extra CLI flags; only those in the allowlist are permitted.
        cfg: optional runtime config overrides.

    Returns:
        dict with keys: tool, target, status, stdout, stderr, exit_code,
        truncated, key_findings, submitted_at (ISO-8601).
    """
    if not target or not target.strip():
        msg = "nikto: target is required"
        return _err(msg)

    if cfg:
        pass  # config-driven overrides handled at server level

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
    else:
        pass

    binary = cfg.get("binary_path", "/usr/bin/nikto") if cfg else "/usr/bin/nikto"
    cmd: List[str] = [binary] + args + [target]

    timeout_sec = cfg.get("timeout_seconds", 300) if cfg else 300
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
                "tool": "nikto",
                "target": target,
                "status": "timeout",
                "stdout": "",
                "stderr": "nikto scan timed out after " + str(timeout_sec) + "s",
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

        # Parse key findings: extract vulnerability IDs and descriptions
        key_findings = _parse_nikto_output(stdout.decode(errors="replace"))

        return {
            "tool": "nikto",
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
            "tool": "nikto",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": "nikto binary not found at " + str(binary),
            "exit_code": 127,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }
    except Exception as e:
        return {
            "tool": "nikto",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }


def _parse_nikto_output(output: str) -> List[str]:
    """Parse nikto output to extract vulnerability findings.

    nikto output lines contain entries like:
    - IP:port / Item Path etc ...
    - Vulnerability ID: e.g. VH123, CC001
    """
    findings: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Look for vulnerability IDs (VH###, CC###, etc.)
        import re
        vuln_ids = re.findall(r"[VV]H\d{3}|[Cc]C\d{3}|[Ii]\d{3}", line)
        for vid in vuln_ids:
            findings.append(vid)
        # Also capture lines that contain common vulnerability indicators
        if any(kw in line.lower() for kw in ["password", "credential", "inject", "xss", "open redirect"]):
            # Truncate long lines
            findings.append(line[:120])
    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            deduped.append(f)
    return deduped[:20]


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _err(msg: str) -> Dict[str, Any]:
    return {
        "tool": "nikto",
        "target": "",
        "status": "failed",
        "stdout": "",
        "stderr": msg,
        "exit_code": -1,
        "truncated": False,
        "key_findings": [],
        "submitted_at": _now_iso(),
    }