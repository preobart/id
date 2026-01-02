import json

from django.conf import settings

import requests


def check_smartcaptcha(token, remote_ip=None):
    server_key = settings.SMARTCAPTCHA_SERVER_KEY
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

