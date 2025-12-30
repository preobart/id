from django.contrib.auth import get_user_model

from ..backends import RedisStaticDevice


User = get_user_model()


def create_verification_device(email):
    return RedisStaticDevice(email)


def generate_and_store_code(email):
    device = create_verification_device(email)
    code = device.generate_token()
    device.store_token(code)
    return str(code)


def verify_code(email, code):
    device = create_verification_device(email)
    return device.verify_token(code)


def is_email_verified(email):
    device = create_verification_device(email)
    return device.is_verified()


def mark_email_verified(email):
    device = create_verification_device(email)
    device.mark_verified()


def clear_verification(email):
    device = create_verification_device(email)
    device.delete()

