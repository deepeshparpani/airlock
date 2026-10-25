import json

def is_network_error(msg: str) -> bool:
    """Checks if error message is an ephemeral network, timeout, or rate-limit failure."""
    if not msg:
        return True
    msg_lower = msg.lower()
    keywords = (
        "stream reading error",
        "software caused connection abort",
        "connection reset",
        "connection refused",
        "connection closed",
        "connection abort",
        "broken pipe",
        "network is unreachable",
        "no route to host",
        "timed out",
        "timeout",
        "deadline_exceeded",
        "deadline exceeded",
        "unavailable",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
        "502",
        "503",
        "504",
        "read tcp",
        "write tcp",
        "dial tcp",
        "temporary failure in name resolution",
        "getaddrinfo",
        "unexpected eof",
        "eof reading",
        "handshake",
        "transport",
        "socket error",
        "reset by peer",
        "resource_exhausted",
        "rate limit",
        "429",
    )
    return any(k in msg_lower for k in keywords)

def extract_json_payload(text: str):
    """Robustly extracts JSON payload from raw text, markdown blocks, or embedded strings."""
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    if "```" in text:
        parts = text.split("```")
        for i in range(1, len(parts), 2):
            block = parts[i]
            if block.startswith("json"):
                block = block[4:]
            block = block.strip()
            try:
                return json.loads(block)
            except Exception:
                pass
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except Exception:
            pass
    return None
