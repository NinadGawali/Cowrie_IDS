"""Flask application exposing Cowrie honeypot analysis APIs and serving dashboard.
Run with: python -m backend.app
"""
from __future__ import annotations
import os
import time
from functools import lru_cache
from typing import Dict, Any

# File system watching for real-time updates
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _WATCHDOG_AVAILABLE = True
except Exception:
    _WATCHDOG_AVAILABLE = False

from flask import Flask, jsonify, send_from_directory, Response
from flask_cors import CORS

from .log_parser import CowrieLogParser
from .summarizer import summarize_logs

LOG_DIR = os.getenv("LOG_DIR", "./cowrie_logs")
REFRESH_SECONDS = int(os.getenv("CACHE_REFRESH", "3"))

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

parser = CowrieLogParser(LOG_DIR)
_cache: Dict[str, Any] = {"ts": 0, "logs": []}
_summary_cache: Dict[str, Any] = {"ts": 0, "data": {}}


# --- Real-time file watcher: update caches when log files change ---
def _prime_logs():
    """Load logs immediately to populate cache."""
    _cache["logs"] = parser.get_recent_logs(limit=400)
    _cache["ts"] = time.time()


if _WATCHDOG_AVAILABLE:
    class _LogDirHandler(FileSystemEventHandler):
        def on_any_event(self, event):
            # Any change under LOG_DIR should prompt a cache refresh
            try:
                _prime_logs()
                # Invalidate summary; recompute on next request
                _summary_cache["ts"] = 0
            except Exception:
                pass

    # Ensure directory exists to avoid observer errors
    os.makedirs(LOG_DIR, exist_ok=True)
    _observer = Observer()
    _observer.schedule(_LogDirHandler(), LOG_DIR, recursive=False)
    _observer.daemon = True
    try:
        _observer.start()
    except Exception:
        # If observer fails (e.g., missing permissions), fall back to timed refresh
        _WATCHDOG_AVAILABLE = False


def _refresh_logs() -> None:
    now = time.time()
    if now - _cache["ts"] > REFRESH_SECONDS:
        _cache["logs"] = parser.get_recent_logs(limit=400)
        _cache["ts"] = now


def _refresh_summary() -> None:
    now = time.time()
    if now - _summary_cache["ts"] > REFRESH_SECONDS:
        _refresh_logs()
        _summary_cache["data"] = summarize_logs(_cache["logs"])
        _summary_cache["ts"] = now


@app.route("/")
def index():
    # Serve the dashboard index.html
    return send_from_directory(app.static_folder, "index.html")


@app.route("/logs")
def logs():
    _refresh_logs()
    return jsonify({"count": len(_cache["logs"]), "data": _cache["logs"]})


@app.route("/stats")
def stats():
    _refresh_logs()
    data = _cache["logs"]
    top_ips: Dict[str, int] = {}
    top_cmds: Dict[str, int] = {}
    creds_attempts: Dict[str, int] = {}
    for r in data:
        ip = r.get("ip")
        cmd = r.get("command")
        user = r.get("username")
        pwd = r.get("password")
        if ip:
            top_ips[ip] = top_ips.get(ip, 0) + 1
        if cmd:
            top_cmds[cmd] = top_cmds.get(cmd, 0) + 1
        if user or pwd:
            cred = f"{user}:{pwd}" if user or pwd else "-"
            creds_attempts[cred] = creds_attempts.get(cred, 0) + 1

    def top_n(d: Dict[str, int], n=10):
        return sorted([{"value": k, "count": v} for k, v in d.items()], key=lambda x: x["count"], reverse=True)[:n]

    return jsonify({
        "total_events": len(data),
        "top_ips": top_n(top_ips),
        "top_commands": top_n(top_cmds),
        "credential_attempts": top_n(creds_attempts),
    })


@app.route("/summary")
def summary():
    _refresh_summary()
    return jsonify(_summary_cache["data"])


# Static assets fallback
@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory(app.static_folder, path)


@app.route('/stream/logs')
def stream_logs():
    """Server-Sent Events (SSE) stream of new log records as they appear.
    This tails the primary cowrie.json file and emits normalized records.
    """
    import glob
    import json

    def pick_log_file() -> str | None:
        # Look for cowrie.json and cowrie.json.* (non-compressed), newest first
        candidates = glob.glob(os.path.join(LOG_DIR, 'cowrie.json'))
        candidates += glob.glob(os.path.join(LOG_DIR, 'cowrie.json.*'))
        candidates = [p for p in candidates if not p.endswith(('.gz', '.xz', '.zip'))]
        if not candidates:
            return None
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return candidates[0]

    def generate():
        last_file = None
        last_size = 0
        while True:
            try:
                log_file = pick_log_file()
                if not log_file:
                    time.sleep(1)
                    continue
                # File rotated or changed
                if log_file != last_file:
                    last_file = log_file
                    last_size = 0

                current_size = os.path.getsize(log_file)
                if current_size < last_size:
                    last_size = 0
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_size)
                    for line in f:
                        last_size = f.tell()
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except Exception:
                            continue
                        record = parser._normalize(evt)
                        # record is a dataclass; convert to dict
                        payload = {
                            'timestamp': record.timestamp,
                            'ip': record.ip,
                            'event_type': record.event_type,
                            'command': record.command,
                            'username': record.username,
                            'password': record.password,
                            'session': record.session,
                            'message': record.message,
                        }
                        yield f"data: {json.dumps(payload)}\n\n"
                time.sleep(1)
            except GeneratorExit:
                break
            except Exception:
                time.sleep(1)
                continue
    return Response(generate(), mimetype='text/event-stream')


if __name__ == "__main__":
    # For local dev without Docker
    app.run(host="0.0.0.0", port=5000, debug=True)
