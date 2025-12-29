import secrets

from django.core.cache import caches


class RedisStaticDevice:
    def __init__(self, email):
        self.email = email
        self.cache = caches["email_verification"]
        self.key_prefix = f"otp_device:{email}"
        self.code_key = f"{self.key_prefix}:code"
        self.attempts_key = f"{self.key_prefix}:attempts"
        self.verified_key = f"email_verified:{email}"

    def generate_token(self, length=6):
        base = 10 ** (length - 1)
        return secrets.randbelow(9 * base) + base
    
    def store_token(self, code):
        self.cache.set(self.code_key, str(code), timeout=15 * 60)
        self.cache.set(self.attempts_key, 3, timeout=15 * 60)

    def verify_token(self, token):
        stored_code = self.cache.get(self.code_key)
        if not stored_code:
            return False

        attempts = self.cache.get(self.attempts_key, 3)
        if attempts <= 0:
            self.cache.delete(self.code_key)
            self.cache.delete(self.attempts_key)
            return False

        if str(stored_code) == str(token):
            self.cache.delete(self.code_key)
            self.cache.delete(self.attempts_key)
            return True

        attempts -= 1
        self.cache.set(self.attempts_key, attempts, timeout=15 * 60)
        return False

    def delete(self):
        self.cache.delete(self.code_key)
        self.cache.delete(self.attempts_key)
        self.cache.delete(self.verified_key)

    def mark_verified(self):
        self.cache.set(self.verified_key, True, timeout=15 * 60)

    def is_verified(self):
        return self.cache.get(self.verified_key, False)

