from datetime import date, datetime
from decimal import Decimal


MAX_BODY_BYTES = 10 * 1024
SENSITIVE_KEYWORDS = ("pass", "token", "secret", "auth", "key", "refresh", "access")

def _is_sensitive_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    lower = key.lower()
    return any(substr in lower for substr in SENSITIVE_KEYWORDS)

def _safe_repr(value, max_len=200):
    try:
        if value is None or isinstance(value, (str, bool, int, float)):
            return value
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, Decimal):
            return str(value)
        if isinstance(value, bytes):
            return f"<binary:{len(value)}b>"
        s = str(value)
        return s if len(s) <= max_len else s[:max_len] + "…"
    except (TypeError, ValueError):
        return "<unserializable>"

def mask_sensitive(data, _depth=0, _max_depth=10, _seen=None):
    if _seen is None:
        _seen = set()
    if _depth > _max_depth:
        return "<max_depth_reached>"
    obj_id = id(data)
    if obj_id in _seen:
        return "<circular>"
    _seen.add(obj_id)

    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if _is_sensitive_key(k):
                out[k] = "***"
            else:
                out[k] = mask_sensitive(v, _depth=_depth + 1, _max_depth=_max_depth, _seen=_seen)
        return out
    if isinstance(data, list):
        return [mask_sensitive(i, _depth=_depth + 1, _max_depth=_max_depth, _seen=_seen) for i in data]
    return _safe_repr(data)