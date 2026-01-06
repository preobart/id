import secrets

from django.conf import settings
from django.core.cache import caches

from .errors import EmailSendError, EmailSendLimitExceededError
from .utils.email_utils import send_code_email


class EmailVerificationManager:
    def __init__(self, email: str, ip_address: str):
        self.email = email
        self.ip_address = ip_address
        self.cache = caches["email_verification"]
        self.code_key = f"code:{email}:{ip_address}"
        self.attempts_key = f"attempts:{email}:{ip_address}"
        self.verified_key = f"verified:{email}:{ip_address}"
        self.send_count_key = f"send_count:{email}:{ip_address}"

    def _generate_token(self, length=None):
        if length is None:
            length = settings.EMAIL_VERIFICATION_CODE_LENGTH
        base = 10 ** (length - 1)
        return str(secrets.randbelow(9 * base) + base)

    def generate_and_store_code(self):
        code = self._generate_token()
        self.cache.set(self.code_key, code, timeout=settings.EMAIL_VERIFICATION_CODE_TTL)
        self.cache.set(self.attempts_key, settings.EMAIL_VERIFICATION_ATTEMPTS, timeout=settings.EMAIL_VERIFICATION_CODE_TTL)
        return code

    def verify_code(self, code: str):
        stored_code = self.cache.get(self.code_key)
        if not stored_code:
            return False

        attempts = self.cache.get(self.attempts_key, settings.EMAIL_VERIFICATION_ATTEMPTS)
        if attempts <= 0:
            self.clear()
            return False

        if stored_code == str(code):
            self.clear()
            return True

        attempts -= 1
        timeout = settings.EMAIL_VERIFICATION_CODE_TTL
        self.cache.set(self.attempts_key, attempts, timeout=timeout)
        self.cache.set(self.code_key, stored_code, timeout=timeout)
        return False

    def is_verified(self):
        return self.cache.get(self.verified_key, False)

    def mark_verified(self):
        self.cache.set(self.verified_key, True, timeout=settings.EMAIL_VERIFICATION_VERIFIED_TTL)

    def clear(self):
        self.cache.delete(self.code_key)
        self.cache.delete(self.attempts_key)
        self.cache.delete(self.verified_key)
        self.cache.delete(self.send_count_key)

    def send_code(self):
        if self.cache.get(self.send_count_key, 0) >= settings.EMAIL_VERIFICATION_SEND_LIMIT:
            raise EmailSendLimitExceededError()
        
        code = self.generate_and_store_code()
        if not send_code_email(self.email, code):
            raise EmailSendError()
        
        try:
            current_count = self.cache.incr(self.send_count_key)
        except ValueError:
            current_count = 1
        
        self.cache.set(self.send_count_key, current_count, timeout=settings.EMAIL_VERIFICATION_SEND_COUNT_TTL)

class LoginLockoutManager:
    def __init__(self, email, ip_address):
        self.email = email
        self.ip_address = ip_address
        self.cache = caches['lockout']
        self.failed_key = f"failed:{email}:{ip_address}"
        self.lockout_key = f"locked:{email}:{ip_address}"
        self.lockout_count_key = f"count:{email}:{ip_address}"

    def is_locked(self):
        return self.cache.get(self.lockout_key, False)

    def get_lockout_time(self):
        lockout_count = self.cache.get(self.lockout_count_key, 1)
        lockout_times = settings.LOCKOUT_TIMES
        if lockout_count > len(lockout_times):
            return lockout_times[-1]
        return lockout_times[lockout_count - 1]

    def record_failed(self):
        failed_ttl = settings.LOCKOUT_FAILED_ATTEMPTS_TTL
        try:
            count = self.cache.incr(self.failed_key)
            self.cache.set(self.failed_key, count, timeout=failed_ttl)
        except ValueError:
            self.cache.set(self.failed_key, 1, timeout=failed_ttl)
            count = 1

        if count >= settings.LOCKOUT_FAILURE_LIMIT:
            old_lockout_count = self.cache.get(self.lockout_count_key, 0)
            lockout_count = old_lockout_count + 1
            self.cache.set(self.lockout_count_key, lockout_count, timeout=settings.LOCKOUT_COUNT_TTL)

            lockout_times = settings.LOCKOUT_TIMES
            if lockout_count > len(lockout_times):
                lockout_time = lockout_times[-1]
            else:
                lockout_time = lockout_times[lockout_count - 1]
            timeout = lockout_time * 60
            self.cache.set(self.lockout_key, True, timeout=timeout)
            self.cache.delete(self.failed_key)
            return True
        return False

    def clear(self):
        self.cache.delete(self.failed_key)
        self.cache.delete(self.lockout_key)
        self.cache.delete(self.lockout_count_key)
