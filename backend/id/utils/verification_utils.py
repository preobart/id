from django.contrib.auth import get_user_model

from ..backends import RedisStaticDevice
from ..errors import CaptchaValidationError, EmailSendError
from .captcha_utils import check_smartcaptcha
from .email_utils import send_code_email


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


def create_password_reset_device(email):
    return RedisStaticDevice(f"password_reset:{email}")


def generate_and_store_password_reset_code(email):
    device = create_password_reset_device(email)
    code = device.generate_token()
    device.store_token(code)
    return str(code)


def verify_password_reset_code(email, code):
    device = create_password_reset_device(email)
    return device.verify_token(code)


def mark_password_reset_verified(email):
    device = create_password_reset_device(email)
    device.mark_verified()


def is_password_reset_verified(email):
    device = create_password_reset_device(email)
    return device.is_verified()


def clear_password_reset(email):
    device = create_password_reset_device(email)
    device.delete()


def validate_captcha(token, remote_ip=None):
    if not check_smartcaptcha(token, remote_ip):
        raise CaptchaValidationError("Invalid or missing captcha")


def send_verification_code(email, code_generator_func):
    code = code_generator_func(email)
    if not send_code_email(email, code):
        raise EmailSendError("Failed to send email")

