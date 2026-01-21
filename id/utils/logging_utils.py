import json
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal

from django.conf import settings

from .ip_utils import get_client_ip


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


def format_timestamp():
    dt = datetime.now(timezone.utc)  # noqa: UP017
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def get_headers(request):
    headers = {}
    for key, value in request.META.items():
        if key.startswith("HTTP_"):
            header_name = key[5:].replace("_", "-").title()
            headers[header_name] = value
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            header_name = key.replace("_", "-").title()
            headers[header_name] = value
    return headers


def get_request_id(request):
    return request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())


def _parse_body(request):
    content_type = request.META.get("CONTENT_TYPE", "") or request.META.get("HTTP_CONTENT_TYPE", "")
    body_bytes = request.body or b""

    if body_bytes and "application/json" in content_type.lower():
        try:
            parsed = json.loads(body_bytes.decode("utf-8"))
            return mask_sensitive(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "unreadable"
    return None


def build_request_log(request, request_id):
    user_id = request.user.pk if request.user.is_authenticated else "anonymous"
    remote_ip = get_client_ip(request)

    headers = get_headers(request)

    request_log = {
        "id": request_id,
        "method": getattr(request, "method", ""),
        "path": getattr(request, "get_full_path", lambda: "")(),
        "user": user_id,
        "remote": remote_ip,
    }

    if headers:
        request_log["headers"] = headers

    body = _parse_body(request)
    if body is not None:
        request_log["body"] = body

    return {
        "ts": format_timestamp(),
        "level": "info",
        "event": "http_request",
        "request": request_log,
    }


def build_error_log(request_id, error, duration_ms):
    return {
        "ts": format_timestamp(),
        "level": "error",
        "event": "exception",
        "request": {"id": request_id},
        "error": str(error),
        "duration_ms": duration_ms,
    }


def build_response_log(request_id, response, duration_ms):
    status_code = getattr(response, "status_code", None)
    reason_phrase = getattr(response, "reason_phrase", "")

    response_data = {
        "status": status_code,
        "reason": reason_phrase,
        "duration_ms": duration_ms,
    }

    if hasattr(response, "data"):
        try:
            response_data["body"] = mask_sensitive(response.data)
        except (AttributeError, TypeError):
            response_data["body"] = "unreadable"

    return {
        "ts": format_timestamp(),
        "level": "info",
        "event": "http_response",
        "request": {"id": request_id},
        "response": response_data,
    }

