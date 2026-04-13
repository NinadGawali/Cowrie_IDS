import os
from typing import List, Dict

from langchain_google_genai import ChatGoogleGenerativeAI

# _GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro-latest")
_GEMINI_MODEL = "gemini-2.5-flash"
_api_key = os.getenv("GOOGLE_API_KEY")

_llm = None
if _api_key:
    try:
        _llm = ChatGoogleGenerativeAI(model=_GEMINI_MODEL, google_api_key=_api_key, temperature=0.2)
    except Exception:
        _llm = None


def build_prompt(parsed_logs: List[Dict]) -> str:
    if not parsed_logs:
        return "No logs available for analysis."
    lines = []
    for l in parsed_logs[:300]:  # safety cap
        ts = l.get("timestamp", "")
        ip = l.get("ip", "")
        cmd = l.get("command") or "(no command)"
        user = l.get("username") or ""
        event = l.get("event_type", "")
        lines.append(f"{ts} | {ip} | {user} | {event} | {cmd}")
    joined = "\n".join(lines)
    return (
        "You are a cybersecurity expert analyzing SSH honeypot logs from Cowrie. "
        "Analyze the attacker behavior, tools used, attack patterns, and potential threats.\n\n"
        "Return a JSON object with these exact keys:\n"
        "- summary: A 2-3 sentence overview of the attack activity\n"
        "- reasoning: A detailed explanation (5-8 sentences) that cites patterns from the logs and explains why the assessed risk level is appropriate\n"
        "- log_context: A compact explanation of what was observed specifically in these latest logs (IPs, commands, event sequence, and suspicious indicators)\n"
        "- tactics: Array of strings describing specific attack techniques observed (e.g., 'Credential brute force', 'Command reconnaissance')\n"
        "- recommendations: Array of actionable security recommendations\n"
        "- risk_level: One of 'low', 'medium', 'high', or 'critical'\n\n"
        "Important constraints:\n"
        "- Use only the provided logs, do not invent unseen activity.\n"
        "- Be specific and evidence-based.\n"
        "- Keep recommendations directly tied to observed attacker behavior.\n\n"
        f"HONEYPOT LOGS:\n{joined}\n\n"
        "Respond ONLY with valid JSON, no markdown formatting."
    )


def summarize_logs(parsed_logs: List[Dict]) -> Dict:
    """Return structured Gemini summary. If Gemini unavailable, return fallback."""
    prompt = build_prompt(parsed_logs)
    if not _llm:
        return {
            "summary": "AI analysis unavailable. Please configure GOOGLE_API_KEY in .env file.",
            "reasoning": "Detailed reasoning is unavailable because the Gemini model is not configured.",
            "log_context": "No model output available.",
            "tactics": [],
            "recommendations": ["Set GOOGLE_API_KEY to enable AI-powered threat analysis"],
            "risk_level": "unknown"
        }
    try:
        resp = _llm.invoke(prompt)
        text = getattr(resp, "content", "") or str(resp)
    except Exception as e:
        return {
            "summary": f"AI analysis failed: {str(e)}",
            "reasoning": "The model call failed before analysis could complete.",
            "log_context": "Unable to derive context due to model request failure.",
            "tactics": [],
            "recommendations": ["Check API key validity and network connectivity"],
            "risk_level": "unknown"
        }

    # Try to parse JSON if model followed instructions
    import json
    import re
    
    # Strip markdown code blocks if present
    text = re.sub(r'^```json\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'^```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()
    
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            # Ensure all expected keys exist
            data.setdefault('summary', 'Analysis completed')
            data.setdefault('reasoning', 'Detailed reasoning not provided by model.')
            data.setdefault('log_context', 'Log context unavailable.')
            data.setdefault('tactics', [])
            data.setdefault('recommendations', [])
            data.setdefault('risk_level', 'medium')
            return data
    except Exception:
        pass

    # Fallback if JSON parsing failed
    return {
        "summary": text[:500] if len(text) > 500 else text,
        "reasoning": "The model did not return valid JSON; summary text shown instead.",
        "log_context": "Could not parse structured context from model output.",
        "tactics": [],
        "recommendations": [],
        "risk_level": "unknown"
    }
