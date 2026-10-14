"""Dirb directory brute-force wrapper for MCP server.

Wraps: dirb -w /usr/share/dirb/wordlists/small.txt (small wordlist only)
Policy: target required; only a small allowlisted set of extra flags may be layered on top.
Note: dirb with large wordlists can exhaust Pi Zero RAM/CPU — keep wordlist small.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, List

DEFAULTS: Dict[str, Any] = {
    "default_args": ["-w", "/usr/share/dirb/wordlists/small.txt"],
    "max_output_kb": 64,
    "allowlisted_flags": {"-X", "-S", "-e", "-r", "-"},
}

DEFAULTS_DIRB_SMALL_WORDLIST = "/usr/share/dirb/wordlists/small.txt"


async def run(target: str, extra_args: List[str] | None = None, cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Run a dirb directory brute-force scan and return structured JSON.

    Args:
        target: target URL (required, e.g. http://example.com/)
        extra_args: extra CLI flags; only those in the allowlist are permitted.
        cfg: optional runtime config overrides.

    Returns:
        dict with keys: tool, target, status, stdout, stderr, exit_code,
        truncated, key_findings, submitted_at (ISO-8601).
    """
    if not target or not target.strip():
        msg = "dirb: target is required"
        return _err(msg)

    if cfg:
        # Apply config overrides if provided
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
        pass  # strip any stale extra args if none provided

    # Check if wordlist file exists; if not, warn but proceed
    binary = cfg.get("binary_path", "/usr/bin/dirb") if cfg else "/usr/bin/dirb"
    wordlist = args[-1] if args else DEFAULTS_DIRB_SMALL_WORDLIST
    if not os.path.isfile(wordlist):
        # Continue anyway; dirb may create the wordlist path dynamically

    cmd: List[str] = [binary] + args + [target]

    timeout_sec = cfg.get("timeout_seconds", 180) if cfg else 180
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
                "tool": "dirb",
                "target": target,
                "status": "timeout",
                "stdout": "",
                "stderr": "dirb scan timed out after " + str(timeout_sec) + "s",
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

        # Parse key findings: extract found paths from dirb output
        key_findings = _parse_dirb_output(stdout.decode(errors="replace"))

        return {
            "tool": "dirb",
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
            "tool": "dirb",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": "dirb binary not found at " + str(binary),
            "exit_code": 127,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }
    except Exception as e:
        return {
            "tool": "dirb",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "truncated": False,
            "key_findings": [],
            "submitted_at": _now_iso(),
        }


def _parse_dirb_output(output: str) -> List[str]:
    """Parse dirb output to extract found paths.

    dirb output lines starting with "/" or containing "CODE" / "SAVE"
    indicate discovered files/directories.
    """
    findings: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # dirb reports found items like "HTTP code 200: /index.html" or just paths
        if line.startswith("/") or line.startswith("http"):
            # Keep just the path portion if it's a full URL
            if line.startswith("http"):
                # Extract path after domain
                parts = line.split()
                for p in parts:
                    if p.startswith("/"):
                        findings.append(p)
            else:
                findings.append(line)
    # Limit findings list size
    return findings[:20]


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _err(msg: str) -> Dict[str, Any]:
    return {
        "tool": "dirb",
        "target": "",
        "status": "failed",
        "stdout": "",
        "stderr": msg,
        "exit_code": -1,
        "truncated": False,
        "key_findings": [],
        "submitted_at": _now_iso(),
    }