"""WhatWeb recon wrapper for MCP server.

Wraps: whatweb --no-geoip --log-verbose=0 (configurable defaults)
Policy: target required; only a small allowlisted set of extra flags may be layered on top.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, List

DEFAULTS: Dict[str, Any] = {
    "default_args": ["--no-geoip", "--log-verbose=0"],
    "max_output_kb": 64,
    "allowlisted_flags": {"-v", "--log-verbose", "--no-geoip"},
}


def configure(cfg: Dict[str, Any]) -> None:
    global DEFAULTS
    if "default_args" in cfg:
        DEFAULTS["default_args"] = list(cfg["default_args"])
    if "max_output_kb" in cfg:
        DEFAULTS["max_output_kb"] = cfg["max_output_kb"]
    if "allowlisted_flags" in cfg:
        DEFAULTS["allowlisted_flags"] = set(cfg["allowlisted_flags"])


async def run(target: str, extra_args: List[str] | None = None, cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not target or not target.strip():
        return {
            "tool": "whatweb",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": "whatweb: target is required",
            "exit_code": -1,
            "truncated": False,
            "submitted_at": _now_iso(),
        }

    if cfg:
        configure(cfg)

    args: List[str] = list(DEFAULTS["default_args"])

    if extra_args:
        allowed = DEFAULTS["allowlisted_flags"]
        filtered: List[str] = []
        for a in extra_args:
            if a in allowed:
                filtered.append(a)
        args.extend(filtered)

    binary = cfg.get("binary_path", "/usr/bin/whatweb") if cfg else "/usr/bin/whatweb"
    cmd: List[str] = [binary] + args + [target]

    timeout_sec = cfg.get("timeout_seconds", 60) if cfg else 60
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
                "tool": "whatweb",
                "target": target,
                "status": "timeout",
                "stdout": "",
                "stderr": "scan timed out after " + str(timeout_sec) + "s",
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
            "tool": "whatweb",
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
            "tool": "whatweb",
            "target": target,
            "status": "failed",
            "stdout": "",
            "stderr": "whatweb binary not found at " + str(binary),
            "exit_code": 127,
            "truncated": False,
            "submitted_at": _now_iso(),
        }
    except Exception as e:
        return {
            "tool": "whatweb",
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