import json
import logging
import time

from .utils.logging_utils import (
    build_error_log,
    build_request_log,
    build_response_log,
    get_request_id,
)


class LoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger("json")

    def __call__(self, request):
        start = time.perf_counter()
        request_id = get_request_id(request)
        
        log_entry = build_request_log(request, request_id)
        self.logger.info(json.dumps(log_entry, ensure_ascii=False))

        try:
            response = self.get_response(request)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start) * 1000)
            err_log = build_error_log(request_id, exc, duration_ms)
            self.logger.exception(json.dumps(err_log, ensure_ascii=False))
            raise

        duration_ms = round((time.perf_counter() - start) * 1000)
        log_entry = build_response_log(request_id, response, duration_ms)
        self.logger.info(json.dumps(log_entry, ensure_ascii=False))
        return response
