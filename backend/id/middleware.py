import json
import logging
import time
import uuid

from .utils import mask_sensitive


logger = logging.getLogger("json")


class LoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger("json")

    def __call__(self, request):
        start = time.perf_counter()
        request_id = request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())

        base = {
            "level": "INFO",
            "event": "request",
            "request_id": request_id,
            "method": getattr(request, "method", ""),
            "path": getattr(request, "get_full_path", lambda: "")(),
            "remote_addr": request.META.get("REMOTE_ADDR"),
            "user_agent": request.META.get("HTTP_USER_AGENT"),
            "user": request.user.pk if request.user.is_authenticated else "anonymous"
        }

        content_type = request.META.get("CONTENT_TYPE", "") or request.META.get("HTTP_CONTENT_TYPE", "")
        body_bytes = request.body or b""

        if body_bytes and "application/json" in content_type.lower():
            try:
                parsed = json.loads(body_bytes.decode("utf-8"))
                base["body"] = mask_sensitive(parsed)
            except (UnicodeDecodeError, json.JSONDecodeError):
                base["body"] = "unreadable"
        else:
            base["body"] = None

        self.logger.info(json.dumps(base, ensure_ascii=False))

        try:
            response = self.get_response(request)
        except Exception as exc:
            duration = round(time.perf_counter() - start, 3)
            err_log = {
                "level": "ERROR",
                "event": "exception",
                "request_id": request_id,
                "exception": str(exc),
                "duration": duration,
                "user": request.user.pk if request.user.is_authenticated else "anonymous"
            }
            self.logger.exception(json.dumps(err_log, ensure_ascii=False))
            raise

        duration = round(time.perf_counter() - start, 3)
        resp_log = {
            "level": "INFO",
            "event": "response",
            "request_id": request_id,
            "status_code": getattr(response, "status_code", None),
            "reason": getattr(response, "reason_phrase", ""),
            "duration": duration,
            "user": request.user.pk if request.user.is_authenticated else "anonymous",
        }

        if hasattr(response, "data"):
            try:
                resp_log["response"] = mask_sensitive(response.data)
            except (AttributeError, TypeError):
                resp_log["response"] = "unreadable"
        else:
            resp_log["response"] = None

        self.logger.info(json.dumps(resp_log, ensure_ascii=False))
        return response