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

    def _generate_token(self, length=6):
        base = 10 ** (length - 1)
        return str(secrets.randbelow(9 * base) + base)

    def generate_and_store_code(self):
        code = self._generate_token()
        self.cache.set(self.code_key, code, timeout=15 * 60)
        self.cache.set(self.attempts_key, 3, timeout=15 * 60)
        return code

    def verify_code(self, code: str):
        stored_code = self.cache.get(self.code_key)
        if not stored_code:
            return False

        attempts = self.cache.get(self.attempts_key, 3)
        if attempts <= 0:
            self.clear()
            return False

        if stored_code == str(code):
            self.clear()
            return True

        attempts -= 1
        self.cache.set(self.attempts_key, attempts, timeout=15 * 60)
        return False

    def is_verified(self):
        return self.cache.get(self.verified_key, False)

    def mark_verified(self):
        self.cache.set(self.verified_key, True, timeout=15 * 60)

    def clear(self):
        self.cache.delete(self.code_key)
        self.cache.delete(self.attempts_key)
        self.cache.delete(self.verified_key)
        self.cache.delete(self.send_count_key)

    def send_code(self):
        current_count = self.cache.get(self.send_count_key, 0)
        if current_count >= 3:
            raise EmailSendLimitExceededError()

        try:
            send_count = self.cache.incr(self.send_count_key)
            if send_count == 1:
                self.cache.set(self.send_count_key, send_count, timeout=60 * 60)
        except (ValueError, TypeError):
            send_count = 1
            self.cache.set(self.send_count_key, send_count, timeout=60 * 60)
        
        if send_count > 3:
            try:
                self.cache.decr(self.send_count_key)
            except (ValueError, TypeError):
                pass
            raise EmailSendLimitExceededError()

        code = self.generate_and_store_code()
        
        if not send_code_email(self.email, code):
            try:
                self.cache.decr(self.send_count_key)
            except (ValueError, TypeError):
                pass
            raise EmailSendError()
        
    


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
        return settings.LOCKOUT_TIMES[lockout_count - 1]

    def record_failed(self):
        failed_ttl = settings.LOCKOUT_FAILED_ATTEMPTS_TTL
        try:
            count = self.cache.incr(self.failed_key)
            self.cache.set(self.failed_key, count, timeout=failed_ttl)
        except ValueError:
            self.cache.set(self.failed_key, 1, timeout=failed_ttl)
            count = 1

        failure_limit = settings.LOCKOUT_FAILURE_LIMIT

        if count >= failure_limit:
            old_lockout_count = self.cache.get(self.lockout_count_key, 0)
            lockout_count = old_lockout_count + 1
            self.cache.set(self.lockout_count_key, lockout_count, timeout=settings.LOCKOUT_COUNT_TTL)

            lockout_times = settings.LOCKOUT_TIMES
            lockout_time = lockout_times[lockout_count - 1]
            timeout = lockout_time if lockout_time > 0 else None
            self.cache.set(self.lockout_key, True, timeout=timeout)
            self.cache.delete(self.failed_key)
            return True
        return False

    def clear(self):
        self.cache.delete(self.failed_key)
        self.cache.delete(self.lockout_key)
        self.cache.delete(self.lockout_count_key)
