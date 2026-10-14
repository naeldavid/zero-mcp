"""DNS recon wrapper for MCP server (dig / nslookup).

Policy: target required; only allowlisted extra flags may be appended.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, List

DEFAULTS: Dict[str, Any] = {
    "dig": {
        "default_args": ["+short"],
        "max_output_kb": 64,
        "allowlisted_flags": {"-x", "+trace", "+noall", "+answer", "+comment"},
    },
    "nslookup": {
        "default_args": [],
        "max_output_kb": 64,
        "allowlisted_flags": {"-type=", "-port=", "-timeout="},
    },
}


def configure(cfg: Dict[str, Any]) -> None:
    """No-op at module level; server applies config per-tool."""


async def run(tool: str, target: str, extra_args: List[str] | None = None, cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not target or not target.strip():
        return {
            "tool": tool,
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": tool + ": target is required",
            "exit_code": -1,
            "truncated": False,
            "submitted_at": _now_iso(),
        }

    if cfg is None:
        cfg = {}

    params = DEFAULTS.get(tool, DEFAULTS["dig"])
    args: List[str] = list(params["default_args"])
    max_bytes = params["max_output_kb"] * 1024
    allowed = params["allowlisted_flags"]

    if extra_args:
        filtered: List[str] = []
        for a in extra_args:
            if a in allowed:
                filtered.append(a)
        args.extend(filtered)

    binary = cfg.get("binary_path", "/usr/bin/dig" if tool == "dig" else "/usr/bin/nslookup") if cfg else ("/usr/bin/dig" if tool == "dig" else "/usr/bin/nslookup")
    cmd: List[str] = [binary] + args + [target]

    timeout_sec = cfg.get("timeout_seconds", 30) if cfg else 30

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
                "tool": tool,
                "target": target,
                "status": "timeout",
                "stdout": "",
                "stderr": "DNS query timed out after " + str(timeout_sec) + "s",
                "exit_code": -1,
                "truncated": True,
                "submitted_at": _now_iso(),
            }

        exit_code = proc.returncode

        if len(stdout) > max_bytes:
            stdout = stdout[-max_bytes:]
            truncated = True
        else:
            truncated = False

        if len(stderr) > max_bytes:
            stderr = stderr[-max_bytes:]

        return {
            "tool": tool,
            "target": target,
            "status": "done" if exit_code == 0 else "failed",
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
            "exit_code": exit_code,
            "truncated": truncated,
            "submitted_at": _now_iso(),
        }

    except FileNotFoundError:
        other = "/usr/bin/nslookup" if tool == "dig" else "/usr/bin/dig"
        return {
            "tool": tool,
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": tool + " binary not found (tried " + binary + ", " + other + ")",
            "exit_code": 127,
            "truncated": False,
            "submitted_at": _now_iso(),
        }
    except Exception as e:
        return {
            "tool": tool,
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