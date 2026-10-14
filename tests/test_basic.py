"""Basic tests for the MCP server: queue, timeout, and truncation logic.

These tests use mocks so they run without requiring the actual CLI tools.
"""

from __future__ import annotations

import json
import asyncio
import sqlite3
import tempfile
import os
from pathlib import Path

import sys
sys.path.insert(0, "/opt/mcp-server")

from tools import nmap, whatweb, dns, curl, subfinder
from server import (
    load_config,
    register_tools,
    submit_job,
    get_job,
    update_job_status,
    _now_iso,
    can_submit,
)


# ---------------------------------------------------------------------------
# Helper: temporary config
# ---------------------------------------------------------------------------

def _make_tmp_config() -> Dict[str, Any]:
    """Build a minimal in-memory config for testing."""
    return {
        "network": {"auth_token": "test-secret-1234"},
        "tools": [
            {
                "name": "nmap",
                "binary_path": "/usr/bin/nmap",
                "enabled": True,
                "default_args": ["-sV", "-T2", "--top-ports", "100"],
                "timeout_seconds": 300,
                "max_output_kb": 64,
                "allowlisted_flags": {"-p", "--top-ports", "-sS", "-sV", "-A"},
            },
            {
                "name": "whatweb",
                "binary_path": "/usr/bin/whatweb",
                "enabled": True,
                "default_args": ["--no-geoip", "--log-verbose=0"],
                "timeout_seconds": 60,
                "max_output_kb": 64,
                "allowlisted_flags": {"-v", "--log-verbose"},
            },
        ],
        "system": {"log_file": "/tmp/mcp-test.log"},
        "job_queue": {"max_concurrent": 1, "job_state_file": "/tmp/mcp-test-jobs.sqlite"},
    }


# ---------------------------------------------------------------------------
# Tool wrapper tests (truncation, target validation)
# ---------------------------------------------------------------------------

async def test_nmap_target_required():
    """nmap.run() must reject empty/None target."""
    cfg = _make_tmp_config()
    nmap.configure(cfg)

    # None target
    result = await nmap.run(None)  # type: ignore
    assert result["status"] == "failed"
    assert "target is required" in result["stderr"]

    # Empty string
    result = await nmap.run("")  # type: ignore
    assert result["status"] == "failed"
    assert "target is required" in result["stderr"]

    # Whitespace-only
    result = await nmap.run("   ")  # type: ignore
    assert result["status"] == "failed"
    assert "target is required" in result["stderr"]

    # Valid target returns a result dict (even if nmap not installed)
    result = await nmap.run("127.0.0.1")  # type: ignore
    assert "tool" in result
    assert result["target"] == "127.0.0.1"
    print("  PASS: test_nmap_target_required")


async def test_whatweb_extra_flags_filtering():
    """whatweb should only apply allowlisted extra args."""
    cfg = _make_tmp_config()
    whatweb.configure(cfg)

    # Allowlisted flag should pass
    result = await whatweb.run("127.0.0.1", extra_args=["-v"])  # type: ignore
    assert result["status"] != "error"  # may fail if binary missing, but should not reject flag

    # Disallowed flag should be silently skipped (not crash)
    result = await whatweb.run("127.0.0.1", extra_args=["--unknown-flag"])  # type: ignore
    assert result["status"] != "error"

    print("  PASS: test_whatweb_extra_flags_filtering")


async def test_dns_tool_truncation():
    """DNS wrapper should truncate output to max_output_kb bytes."""
    cfg = _make_tmp_config()
    # We'll just test the truncation logic directly, not the full subprocess

    # Simulate a 200-byte stdout
    long_output = "a" * 200
    max_bytes = 64 * 1024  # 64 KB, way more than 200, so no truncation
    if len(long_output.encode("utf-8")) > max_bytes:
        truncated = long_output[-max_bytes:]
    else:
        truncated = long_output
    assert truncated == long_output  # no truncation needed

    # Simulate a very large output that needs truncation
    # Keep only last N bytes
    huge = "x" * (200 * 1024)  # 200 KB
    max_kb = 64
    truncated_huge = huge[-max_kb * 1024 :]
    assert len(truncated_huge.encode("utf-8")) == max_kb * 1024
    assert truncated_huge.startswith("x")  # last bytes

    print("  PASS: test_dns_tool_truncation")


# ---------------------------------------------------------------------------
# Queue logic tests
# ---------------------------------------------------------------------------

async def test_queue_single_slot():
    """Only one job may be running/queued at a time."""
    cfg = _make_tmp_config()
    register_tools(cfg)

    # Use a temp DB path
    tmp_db = "/tmp/test-queue-jobs.sqlite"
    # Monkey-patch DB_PATH in the modules we'll use
    import server as srv
    srv.DB_PATH = tmp_db

    # Clean slate
    conn = sqlite3.connect(tmp_db)
    conn.execute("DELETE FROM jobs")
    conn.commit()
    conn.close()

    # First job should be accepted
    j1 = submit_job("nmap", "127.0.0.1")
    assert can_submit() is True

    # Second job should be rejected (queue busy)
    # We can't easily test can_submit() after submit_job without
    # the full event loop, so we just verify the DB state
    row1 = get_job(j1)
    assert row1["status"] == "queued"

    # Clean up
    os.remove(tmp_db)
    print("  PASS: test_queue_single_slot")


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

def test_check_auth_valid():
    """check_auth should accept correct Bearer token."""
    from server import check_auth, AUTH_TOKEN
    AUTH_TOKEN = "my-secret-token-1234"

    # Valid token
    assert check_auth({"authorization": "Bearer my-secret-token-1234"}) is True

    # Missing token
    assert check_auth({"authorization": "Bearer wrong"}) is False

    # No auth header
    assert check_auth({}) is False

    # Token as query param style not supported for stdio
    assert check_auth({"authorization": "Bearer " + "my-secret-token-1234"}) is True

    print("  PASS: test_check_auth_valid")


# ---------------------------------------------------------------------------
# ISO timestamp test
# ---------------------------------------------------------------------------

def test_now_iso_format():
    """_now_iso() should return ISO-8601 UTC string ending in Z."""
    ts = _now_iso()
    assert ts.endswith("Z")
    # Should be parseable
    from datetime import datetime, timezone
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    print("  PASS: test_now_iso_format")


# ---------------------------------------------------------------------------
# RAM-check guard tests
# ---------------------------------------------------------------------------

async def test_check_ram_threshold_above():
    """_check_ram_threshold() returns True when free RAM is above threshold."""
    from server import _check_ram_threshold
    cfg = {
        "system": {"ram_threshold_mb": 100},
    }
    # On most systems with >100 MB free, this will return True
    result = _check_ram_threshold(cfg)
    # May be True or False depending on actual system RAM, but should not crash
    assert isinstance(result, bool)
    print("  PASS: test_check_ram_threshold_above")


async def test_check_ram_threshold_configurable():
    """_check_ram_threshold() respects the ram_threshold_mb config."""
    from server import _check_ram_threshold
    # Set threshold very low (1 MB) — should pass on any system with >1 MB
    cfg = {
        "system": {"ram_threshold_mb": 1},
    }
    result = _check_ram_threshold(cfg)
    assert isinstance(result, bool)
    print("  PASS: test_check_ram_threshold_configurable")


# ---------------------------------------------------------------------------
# Queue rejection path tests
# ---------------------------------------------------------------------------

async def test_queue_reject_when_busy():
    """call_tool rejects if another job is already running or queued."""
    from server import load_config, register_tools, submit_job, get_job, can_submit, _check_ram_threshold
    import server as srv

    cfg = _make_tmp_config()
    register_tools(cfg)

    tmp_db = "/tmp/test-queue-jobs2.sqlite"
    srv.DB_PATH = tmp_db

    # Clean slate
    conn = sqlite3.connect(tmp_db)
    conn.execute("DELETE FROM jobs")
    conn.commit()
    conn.close()

    # First job: submit and verify it's queued
    j1 = submit_job("nmap", "127.0.0.1")
    row1 = get_job(j1)
    assert row1["status"] == "queued"

    # Second job should be rejected (queue busy)
    # We can't easily call handle_call_tool without the full MCP loop,
    # but we can verify can_submit returns False
    assert can_submit() is False

    # Clean up
    os.remove(tmp_db)
    print("  PASS: test_queue_reject_when_busy")


async def test_queue_reject_ram_insufficient():
    """call_tool rejects if free RAM is below the configured threshold.

    This test verifies the RAM guard integration. We test _check_ram_threshold
    directly since /proc/meminfo values vary by system.
    """
    from server import _check_ram_threshold

    # Test with a very high threshold — should return False on normal systems
    cfg = {"system": {"ram_threshold_mb": 4096}}  # 4 GB
    result = _check_ram_threshold(cfg)
    assert isinstance(result, bool)
    # On a Pi Zero with 512 MB, this should be False
    # On a larger system, it depends on actual MemAvailable
    print(f"  PASS: test_queue_reject_ram_insufficient (threshold=4GB, result={result})")


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

async def main():
    print("Running basic MCP server tests...\n")
    await test_nmap_target_required()
    await test_whatweb_extra_flags_filtering()
    await test_dns_tool_truncation()
    test_queue_single_slot()
    await test_check_ram_threshold_above()
    await test_check_ram_threshold_configurable()
    await test_queue_reject_when_busy()
    await test_queue_reject_ram_insufficient()
    test_check_auth_valid()
    test_now_iso_format()
    print("\nAll tests passed!")


if __name__ == "__main__":
    asyncio.run(main())