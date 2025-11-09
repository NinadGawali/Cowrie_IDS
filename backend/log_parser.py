import json
import os
import glob
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class LogRecord:
    timestamp: str
    ip: Optional[str]
    event_type: Optional[str]
    command: Optional[str]
    username: Optional[str]
    password: Optional[str]
    session: Optional[str]
    message: Optional[str]
    raw: Dict[str, Any]


class CowrieLogParser:
    """
    Parse Cowrie JSON line logs from a directory.
    Cowrie emits JSON events (one per line) typically in files like:
      - cowrie.json
      - cowrie.json.1, cowrie.json.2.gz, etc.
    We focus on non-gz JSONL files by default.
    """

    def __init__(self, log_dir: str) -> None:
        self.log_dir = log_dir

    def _candidate_files(self) -> List[str]:
        patterns = [
            os.path.join(self.log_dir, "cowrie.json"),
            os.path.join(self.log_dir, "cowrie.json.*"),
        ]
        files: List[str] = []
        for p in patterns:
            files.extend(glob.glob(p))
        # Exclude compressed files
        files = [f for f in files if not f.endswith((".gz", ".xz", ".zip"))]
        # Sort by mtime desc (newest first)
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        return files

    def _iter_json_lines(self, filepath: str) -> Iterable[Dict[str, Any]]:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        # Skip junk
                        continue
        except FileNotFoundError:
            return
        except Exception:
            return

    @staticmethod
    def _isoformat(ts: Optional[str]) -> str:
        if not ts:
            return ""
        try:
            # Cowrie timestamps are usually ISO8601 already
            # but normalize if possible
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.isoformat()
        except Exception:
            return ts

    @staticmethod
    def _normalize(event: Dict[str, Any]) -> LogRecord:
        eventid = event.get("eventid")
        ip = event.get("src_ip") or event.get("peer_ip")
        username = event.get("username")
        password = event.get("password")
        session = event.get("session")
        command = None

        # Extract command for relevant events
        if eventid in {"cowrie.command.input", "cowrie.command.failed"}:
            command = event.get("input") or event.get("command")

        msg = event.get("message")
        ts = event.get("timestamp") or event.get("time")

        return LogRecord(
            timestamp=CowrieLogParser._isoformat(ts),
            ip=ip,
            event_type=eventid,
            command=command,
            username=username,
            password=password,
            session=session,
            message=msg,
            raw=event,
        )

    def get_recent_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return up to `limit` normalized records across log files, newest first.
        We do a simple scan in newest-first file order and keep the last N records.
        """
        results: List[LogRecord] = []
        for fp in self._candidate_files():
            for evt in self._iter_json_lines(fp):
                results.append(self._normalize(evt))
                if len(results) >= limit:
                    break
            if len(results) >= limit:
                break

        # Sort descending by timestamp string (ISO should sort lexically)
        results.sort(key=lambda r: r.timestamp or "", reverse=True)
        return [asdict(r) for r in results]
