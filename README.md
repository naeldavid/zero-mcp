# MCP Server for Raspberry Pi Zero W

Lightweight Model Context Protocol (MCP) server that wraps a small set of CLI
recon tools. Designed to run on a Pi Zero W (512 MB RAM, single-core ARMv6,
1 GHz) with Raspberry Pi OS Lite (32-bit).

## Why this design for Pi Zero?

- **No X11 / graphics stack** — the Pi Zero has no GPU headroom for a GUI;
  this is a headless CLI service only.
- **Standard library + asyncio** — no pandas, numpy, or other heavy deps. The
  only third-party dependency is the `mcp` SDK (optional; the server runs
  purely on the stdlib + `mcp` if installed).
- **SQLite job state** — survives kill/restart via systemd without losing
  in-flight job tracking. Writes are minimised: only one small row per job
  (max ~64 KB truncated output).
- **Single-slot job queue** — only one scan at a time. Prevents resource
  exhaustion and Wi‑Fi storming on the limited CPU/bandwidth.
- **Rotating log files** — 1 MB max per file, 5 backups, to protect SD card
  write endurance.

## Installation (Pi Zero W, Raspberry Pi OS Lite 32-bit)

### 1. Prerequisites

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Python 3 + minimal tools
sudo apt install -y python3 python3-pip

# Ensure required CLI tools are installed (authorised-recon only)
sudo apt install -y nmap whatweb dnsutils curl subfinder

# Install the mcp SDK (optional — server works without it; provides
# the /mcp/* endpoints if desired)
pip3 install mcp-sdk  # or whatever the correct package name is
```

### 2. Get the server code

```bash
git clone https://github.com/your-repo/mcp-server.git /opt/mcp-server
cd /opt/mcp-server
```

### 3. Install CLI tools (authorised-recon only)

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Python 3 + minimal tools
sudo apt install -y python3 python3-pip

# Install CLI tools from apt (Raspberry Pi OS repos):
#   nmap, whatweb, dnsutils, curl, subfinder — these are light and safe on Pi Zero
sudo apt install -y nmap whatweb dnsutils curl subfinder

# dirb — included in repos with small wordlist by default
sudo apt install -y dirb

# nikto — available but RAM-intensive; see notes below
sudo apt install -y nikto

# ssl/tls checks: sslscan is in apt; testssl.sh is recommended but requires manual install
#   sslscan:   sudo apt install -y sslscan
#   testssl.sh: git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
#               NOTE: testssl.sh is NOT recommended on Pi Zero due to CPU/memory intensity.
#               Run from a more powerful box over Tailscale instead.

# NOTE: Pi Zero (512 MB RAM) cannot safely run nikto or testssl.sh — these are
#       heavyweight scanners. If you need them, run from a more powerful machine
#       over Tailscale. On the Zero, only nmap (with -sV -T2 --top-ports 100),
#       whatweb, dirb (small wordlist), curl, dnsrecon, and dns tools are recommended.

# Install the mcp SDK (optional — server works without it; provides
# the /mcp/* endpoints if desired)
pip3 install mcp-sdk  # or whatever the correct package name is
```

### 4. Systemd service

```bash
sudo cp /opt/mcp-server/systemd/mcp-server.service /etc/systemd/system/mcp-server.service
sudo systemctl daemon-reload
sudo systemctl enable mcp-server.service
sudo systemctl start mcp-server.service
```

Check status:

```bash
systemctl status mcp-server.service
journalctl -u mcp-server.service -f
```

### 5. Firewall / Tailscale

If reaching the server over Tailscale, ensure the Pi's Tailscale IP is reachable.
The default config binds to `"local"` (127.0.0.1). To bind to the Tailscale
interface, edit `config.example.toml`:

```toml
bind = "tailscale"
```

The service user (`mcp`) must be a member of the `tailscale` group if you
use the Tailscale network kernel driver, or you can bind to `100.64.0.0/10`
explicitly.

### 6. SD card endurance notes

- Log rotation is pre-configured: `log_max_bytes = 1048576` (1 MB) and
  `log_backup_count = 5` in `config.example.toml`.
- Job state lives in SQLite at `/var/lib/mcp-server/jobs.sqlite` — a single
  file with a few rows; writes are infrequent.
- If you need to further reduce writes, set `log_backup_count = 0` and/or
  mount `/var/log/` and `/var/lib/` with `commit=1` or `sync` options *only*
  if you understand the performance trade-off.

## Protocol (JSON-RPC 2.0 over stdio)

The server communicates via the Model Context Protocol using JSON-RPC 2.0
messages on stdin/stdout. Each line is a complete message.

### Messages

**initialize**

```json
{
  "jsonrpc": "2.0",
  "id": "init-1",
  "method": "initialize",
  "params": {}
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": "init-1",
  "result": {
    "server_info": {"name": "mcp-server", "version": "0.1.0"},
    "capabilities": {"tools": {}}
  }
}
```

**list_tools**

```json
{
  "jsonrpc": "2.0",
  "id": "list-1",
  "method": "list_tools",
  "params": {}
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": "list-1",
  "result": {"tools": ["nmap", "whatweb", "dns", "curl", "subfinder"]}
}
```

**call_tool** — submit a scan job

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "call_tool",
  "params": {
    "tool": "nmap",
    "target": "192.168.1.1",
    "extra_args": ["-p", "80"]
  }
}
```

Response (queued immediately; runs single-slot):

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "result": {
    "job_id": "c1db2e8a-...",
    "status": "queued",
    "message": "job submitted to single-slot queue"
  }
}
```

**get_status** — check a job

```json
{
  "jsonrpc": "2.0",
  "id": "status-1",
  "method": "get_status",
  "params": {"job_id": "c1db2e8a-..."}
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": "status-1",
  "result": {
    "job_id": "c1db2e8a-...",
    "tool": "nmap",
    "target": "192.168.1.1",
    "status": "done",
    "submitted_at": "2026-10-10T12:34:56Z",
    "started_at": "2026-10-10T12:35:01Z",
    "finished_at": "2026-10-10T12:35:42Z",
    "result_text": "... truncated nmap output (last 64 KB) ...",
    "result_path": null
  }
}
```

**cancel_job** — cancel a running job

```json
{
  "jsonrpc": "2.0",
  "id": "cancel-1",
  "method": "cancel_job",
  "params": {"job_id": "c1db2e8a-..."}
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": "cancel-1",
  "result": {"job_id": "c1db2e8a-...", "status": "cancelled", "message": "job cancelled"}
}
```

**Auth**: add `"Authorization: Bearer <token>"` header to any message.
The token is the `auth_token` value from `config.example.toml`.

## Config

See `config.example.toml`. Key sections:

- `network.bind` — "local" (127.0.0.1), "wlan0", or "tailscale"
- `network.auth_token` — generated once via `openssl rand -hex 32`
- `[[tools]]` — each entry has `name`, `binary_path`, `enabled`, 
  `default_args`, `timeout_seconds`, `max_output_kb`, and optional
  `allowlisted_flags` sub-entries.
- `system.log_file`, `system.log_max_bytes`, `system.log_backup_count`
- `job_queue.max_concurrent` — always 1 (enforced in code)

## Tools wrapped (config-driven)

| Tool      | Default args                              | Timeout | Max output | Notes                                          |
|-----------|-------------------------------------------|---------|------------|------------------------------------------------|
| nmap      | -sV -T2 --top-ports 100                  | 300s    | 64 KB      | Network/service recon                          |
| whatweb   | --no-geoip --log-verbose=0               | 60s     | 64 KB      | Web fingerprinting                           |
| dirb      | -w /usr/share/dirb/wordlists/small.txt  | 180s    | 64 KB      | Dir brute-force; small wordlist only on Pi Zero|
| nikto     | -Tuning 123b                             | 300s    | 64 KB      | Web vuln scan; heavy — avoid on Pi Zero        |
| ssl       | (none)                                    | 120s    | 64 KB      | TLS config checks; sslscan in apt, testssl.sh   |
|           |                                           |         |            | manual install, NOT recommended on Pi Zero     |
| dnsrecon  | -t A,AAAA,MX,NS,SOA                       | 120s    | 64 KB      | DNS enumeration                              |
| dns (dig) | +short                                    | 30s     | 64 KB      | DNS queries                                  |
| nslookup  | (none)                                    | 30s     | 64 KB      | DNS lookups                                  |
| curl      | -sS                                       | 60s     | 64 KB      | HTTP probing                                 |
| subfinder | -silent                                   | 120s    | 64 KB      | Subdomain enumeration                        |

Extra flags beyond `default_args` must be from the per-tool `allowlisted_flags`
set. Any unknown flag causes the submission to be rejected. This prevents
flag-abuse (e.g., `-oX /etc/passwd`) from an AI client.

## Troubleshooting

- `systemctl status mcp-server.service` — check service health.
- `journalctl -u mcp-server.service -n 50` — recent logs.
- If the server won't start, check that all CLI tools are on PATH and
  executable by the `mcp` user.
- If `call_tool` returns "job queue busy", wait for the current scan to finish
  or cancel it first via `cancel_job`.
- Output is truncated to the last 64 KB. If a tool's full output is needed,
  run it directly on the Pi console.