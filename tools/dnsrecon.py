"""DNS reconnaissance wrapper for MCP server (dnsrecon).

Wraps: dnsrecon (from dnsutils package)
Policy: target required; only allowlisted extra flags may be appended.
Timeout: 120s.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, List

DEFAULTS: Dict[str, Any] = {
    "default_args": ["-t", "A,AAAA,MX,NS,SOA"],
    "max_output_kb": 64,
    "allowlisted_flags": {"-t", "-n", "-w", "-s", "-d", "-l", "-j", "-u"},
}

DEFAULTS_DNSRECON_TARGS = "A,AAAA,MX,NS,SOA"


async def run(target: str, extra_args: List[str] | None = None, cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Run a dnsrecon DNS enumeration and return structured JSON.

    Args:
        target: domain name (required, e.g. example.com)
        extra_args: extra CLI flags; only those in the allowlist are permitted.
        cfg: optional runtime config overrides.

    Returns:
        dict with keys: tool, target, status, stdout, stderr, exit_code,
        truncated, key_findings, submitted_at (ISO-8601).
    """
    if not target or not target.strip():
        msg = "dnsrecon: target is required"
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

    binary = cfg.get("binary_path", "/usr/bin/dnsrecon") if cfg else "/usr/bin/dnsrecon"
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
                "tool": "dnsrecon",
                "target": target,
                "status": "timeout",
                "stdout": "",
                "stderr": "dnsrecon enumeration timed out after " + str(timeout_sec) + "s",
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

        # Parse key findings: extract DNS records and host info
        key_findings = _parse_dnsrecon_output(stdout.decode(errors="replace"))

        return {
            "tool": "dnsrecon",
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
            "tool": "dnsrecon",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": "dnsrecon binary not found at " + str(binary) + " (install: sudo apt install dnsutils)",
            "exit_code": 127,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }
    except Exception as e:
        return {
            "tool": "dnsrecon",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }


def _parse_dnsrecon_output(output: str) -> List[str]:
    """Parse dnsrecon output to extract DNS record findings.

    dnsrecon output contains lines with record types and values.
    """
    findings: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        # A/AAAA records
        if "a record" in low or "aaa record" in low or line.startswith("A ") or line.startswith("AAAA"):
            findings.append(line[:150])
        # MX records
        elif "mx record" in low or line.startswith("MX ") or "mail" in low:
            findings.append(line[:150])
        # NS records
        elif "ns record" in low or "name server" in low or line.startswith("NS "):
            findings.append(line[:150])
        # SOA records
        elif "soa record" in low or "start of authority" in low:
            findings.append(line[:150])
        # TXT records
        elif "txt record" in low or "text record" in low:
            findings.append(line[:150])
        # CNAME
        elif "cname" in low or "alias" in low:
            findings.append(line[:150])
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
        "tool": "dnsrecon",
        "target": "",
        "status": "failed",
        "stdout": "",
        "stderr": msg,
        "exit_code": -1,
        "truncated": False,
        "key_findings": [],
        "submitted_at": _now_iso(),
    }