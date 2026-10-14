"""Nmap recon wrapper for MCP server.

Wraps: nmap -sV -T2 --top-ports 100 (configurable defaults)
Policy: target required; only a small allowlisted set of extra flags may be layered on top.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, List

# The wrapper receives its config from the server at runtime via the
# `configure` hook, so we keep module-level defaults minimal.
DEFAULTS: Dict[str, Any] = {
    "default_args": ["-sV", "-T2", "--top-ports", "100"],
    "max_output_kb": 64,
    "allowlisted_flags": {"-p", "--top-ports", "--script", "-sS", "-sV", "-A", "-oA", "-oX"},
}


def configure(cfg: Dict[str, Any]) -> None:
    """Apply server-level config overrides."""
    global DEFAULTS
    if "default_args" in cfg:
        DEFAULTS["default_args"] = list(cfg["default_args"])
    if "max_output_kb" in cfg:
        DEFAULTS["max_output_kb"] = cfg["max_output_kb"]
    if "allowlisted_flags" in cfg:
        DEFAULTS["allowlisted_flags"] = set(cfg["allowlisted_flags"])


async def run(target: str, extra_args: List[str] | None = None, cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Run an nmap recon scan and return structured JSON.

    Args:
        target: hostname, IP, or CIDR range (required).
        extra_args: extra CLI flags; only those in the allowlist are permitted.
        cfg: optional runtime config overrides.

    Returns:
        dict with keys: tool, target, status, stdout, stderr, exit_code,
        truncated, submitted_at (ISO-8601).
    """
    if not target or not target.strip():
        msg = "nmap: target is required"
        return _err(msg)

    if cfg:
        configure(cfg)

    args: List[str] = list(DEFAULTS["default_args"])

    # Apply allowlisted extra args
    if extra_args:
        allowed = DEFAULTS["allowlisted_flags"]
        filtered: List[str] = []
        for a in extra_args:
            if a in allowed:
                filtered.append(a)
            else:
                # reject unknown flag silently (or could return error)
                pass
        args.extend(filtered)
    else:
        # strip any stale extra args if none provided
        pass

    binary = cfg.get("binary_path", "/usr/bin/nmap") if cfg else "/usr/bin/nmap"
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
                "tool": "nmap",
                "target": target,
                "status": "timeout",
                "stdout": "",
                "stderr": "scan timed out after " + str(timeout_sec) + "s",
                "exit_code": -1,
                "truncated": True,
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
        else:
            pass

        return {
            "tool": "nmap",
            "target": target,
            "status": "done" if exit_code == 0 else "failed",
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
            "exit_code": exit_code,
            "truncated": truncated,
            "submitted_at": _now_iso(),
        }

    except FileNotFoundError:
        return {
            "tool": "nmap",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": "nmap binary not found at " + str(binary),
            "exit_code": 127,
            "truncated": False,
            "submitted_at": _now_iso(),
        }
    except Exception as e:
        return {
            "tool": "nmap",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "truncated": False,
            "submitted_at": _now_iso(),
        }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _err(msg: str) -> Dict[str, Any]:
    return {
        "tool": "nmap",
        "target": "",
        "status": "failed",
        "stdout": "",
        "stderr": msg,
        "exit_code": -1,
        "truncated": False,
        "submitted_at": _now_iso(),
    }