import re

from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address


ipv4_with_port = re.compile(r"^(\d+\.\d+\.\d+\.\d+):\d+")
ipv6_with_port = re.compile(r"^\[([^\]]+)\]:\d+")


def is_valid_ip(ip_address):
    if not ip_address:
        return False
    ip_address = ip_address.strip()
    try:
        validate_ipv46_address(ip_address)
        return True
    except ValidationError:
        return False


def get_ip_address_from_request(request) -> str:
    remote_addr = request.META.get("REMOTE_ADDR", "")
    if remote_addr and is_valid_ip(remote_addr):
        return remote_addr.strip()
    return "127.0.0.1"

def strip_port_number(ip_address_string: str) -> str:
    if not ip_address_string:
        return ip_address_string

    ip_address = None

    if ipv4_with_port.match(ip_address_string):
        match = ipv4_with_port.match(ip_address_string)
        if match:
            ip_address = match[1]
    elif ipv6_with_port.match(ip_address_string):
        match = ipv6_with_port.match(ip_address_string)
        if match:
            ip_address = match[1]

    if ip_address and is_valid_ip(ip_address):
        return ip_address

    return ip_address_string


def get_client_ip(request) -> str:
    if not request:
        return "127.0.0.1"

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(",")[0].strip()
        ip_address = strip_port_number(ip_address)
        if is_valid_ip(ip_address):
            return ip_address

    ip_address = get_ip_address_from_request(request)
    return ip_address
