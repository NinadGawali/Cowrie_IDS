from __future__ import annotations
import os
import time
import json
import glob
from typing import Dict, Any

from flask import Flask, jsonify, send_from_directory, Response, request
from flask_cors import CORS

from .log_parser import CowrieLogParser
from .summarizer import summarize_logs
from .attack_classifier import AttackClassifier

LOG_DIR = os.getenv("LOG_DIR", "./cowrie_logs")
REFRESH_SECONDS = 10

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

parser = CowrieLogParser(LOG_DIR)
classifier = AttackClassifier()

_cache: Dict[str, Any] = {"ts": 0, "logs": []}
_prediction_cache = {}


# ✅ Prediction cache (major CPU optimization)
def get_prediction(cmd):
    if not cmd:
        return {}
    if cmd in _prediction_cache:
        return _prediction_cache[cmd]

    pred = classifier.classify_command(cmd)
    _prediction_cache[cmd] = pred
    return pred


def _with_predictions(rows):
    enriched = []
    for row in rows:
        item = dict(row)
        item.update(get_prediction(row.get("command")))
        enriched.append(item)
    return enriched


def _refresh_logs():
    now = time.time()
    if now - _cache["ts"] > REFRESH_SECONDS:
        logs = parser.get_recent_logs(limit=100)
        _cache["logs"] = _with_predictions(logs)
        _cache["ts"] = now


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/logs")
def logs():
    _refresh_logs()
    return jsonify({
        "count": len(_cache["logs"]),
        "data": _cache["logs"]
    })


@app.route("/stats")
def stats():
    _refresh_logs()
    data = _cache["logs"]

    top_ips, top_cmds, creds_attempts, attack_labels = {}, {}, {}, {}

    for r in data:
        ip = r.get("ip")
        cmd = r.get("command")
        user = r.get("username")
        pwd = r.get("password")
        label = r.get("attack_label")

        if ip:
            top_ips[ip] = top_ips.get(ip, 0) + 1
        if cmd:
            top_cmds[cmd] = top_cmds.get(cmd, 0) + 1
        if user or pwd:
            cred = f"{user}:{pwd}"
            creds_attempts[cred] = creds_attempts.get(cred, 0) + 1
        if label:
            attack_labels[label] = attack_labels.get(label, 0) + 1

    def top_n(d, n=10):
        return sorted(
            [{"value": k, "count": v} for k, v in d.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:n]

    return jsonify({
        "total_events": len(data),
        "top_ips": top_n(top_ips),
        "top_commands": top_n(top_cmds),
        "credential_attempts": top_n(creds_attempts),
        "attack_labels": top_n(attack_labels),
        "model": {
            "available": classifier.available,
            "error": classifier.error
        }
    })


@app.route("/summary")
def summary():
    limit = request.args.get("limit", default=10, type=int)
    _refresh_logs()
    logs = _cache["logs"][:limit]
    data = summarize_logs(logs)
    return jsonify(data)


# ✅ FIXED SSE (no CPU spike + no crash)
@app.route('/stream/logs')
def stream_logs():
    def pick_file():
        files = glob.glob(os.path.join(LOG_DIR, "cowrie.json"))
        return files[0] if files else None

    def generate():
        last_size = 0

        while True:
            try:
                file = pick_file()
                if not file:
                    time.sleep(2)
                    continue

                with open(file, 'r') as f:
                    f.seek(last_size)

                    while True:
                        line = f.readline()
                        if not line:
                            break

                        last_size = f.tell()

                        try:
                            evt = json.loads(line)
                        except:
                            continue

                        record = parser._normalize(evt)

                        payload = {
                            "timestamp": record.timestamp,
                            "ip": record.ip,
                            "command": record.command
                        }

                        payload.update(get_prediction(record.command))

                        yield f"data: {json.dumps(payload)}\n\n"

                time.sleep(2)

            except GeneratorExit:
                break
            except:
                time.sleep(2)

    return Response(generate(), mimetype='text/event-stream')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)