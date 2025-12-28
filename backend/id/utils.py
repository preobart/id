import json
import os
from datetime import date, datetime
from decimal import Decimal

from django.conf import settings

import requests


def _is_sensitive_key(key):
    if not isinstance(key, str):
        return False
    lower = key.lower()
    return any(substr in lower for substr in settings.SENSITIVE_KEYWORDS)

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

def check_smartcaptcha(token, remote_ip=None):
    server_key = settings.SMARTCAPTCHA_SERVER_KEY
    if not server_key:
        return True

    if not token:
        return False

    data = {
        "secret": server_key,
        "token": token,
    }
    if remote_ip:
        data["ip"] = remote_ip

    try:
        response = requests.post(settings.SMARTCAPTCHA_VERIFY_URL, data=data, timeout=1)
        server_output = response.content.decode()

        if response.status_code != 200:
            return False

        result = json.loads(server_output)
        return result.get("status") == "ok"
    except (requests.RequestException, ValueError, KeyError, json.JSONDecodeError):
        return False