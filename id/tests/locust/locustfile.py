import os
import random
import string
import time
import uuid

import django
from django.core.cache import caches
from locust import HttpUser, TaskSet, between, task  # pyright: ignore[reportAttributeAccessIssue]

os.environ.setdefault("DJANGO_SETTINGS_MODULE", os.getenv("DJANGO_SETTINGS_MODULE", "id.settings.test"))
django.setup()


def generate_email():
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


def generate_password():
    return "".join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=12))


def get_verification_code(email, ip_address, code_type):
    cache = caches["email_verification"]
    code_key = f"{code_type}:code:{email}:{ip_address}"
    max_attempts = 10
    for _ in range(max_attempts):
        code = cache.get(code_key)
        if code:
            return code
        time.sleep(0.1)
    return None


class AnonymousUserTasks(TaskSet):
    def on_start(self):
        self.csrf_token = None
        self.get_csrf_token()

    def get_csrf_token(self):
        with self.client.get("/auth/csrf", name="get_csrf_token", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get("token")
                if self.csrf_token:
                    self.client.headers.update({"X-CSRFToken": self.csrf_token})
                response.success()
            else:
                response.failure(f"Expected 200, got {response.status_code}")

    @task(5)
    def get_feature_flags(self):
        with self.client.get("/feature-flags", name="get_feature_flags", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code < 500:
                response.failure(f"Expected 200, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(3)
    def check_email(self):
        if not self.csrf_token:
            self.get_csrf_token()
        email = generate_email()
        with self.client.post(
            "/auth/check-email",
            json={"email": email},
            name="check_email",
            catch_response=True,
        ) as response:
            if response.status_code in (200, 404):
                response.success()
            elif response.status_code < 500:
                response.failure(f"Expected 200 or 404, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(2)
    def send_code_email_verification(self):
        if not self.csrf_token:
            self.get_csrf_token()
        email = generate_email()
        ip_address = f"127.0.0.{random.randint(1, 255)}"
        with self.client.post(
            "/auth/send-code",
            json={"email": email, "code_type": "email_verification"},
            headers={"X-Forwarded-For": ip_address},
            name="send_code_email_verification",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 429:
                response.failure("Rate limit exceeded")
            elif response.status_code == 500:
                response.failure("Email send error")
            elif response.status_code < 500:
                response.failure(f"Expected 200, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(2)
    def send_code_password_reset(self):
        if not self.csrf_token:
            self.get_csrf_token()
        email = generate_email()
        ip_address = f"127.0.0.{random.randint(1, 255)}"
        with self.client.post(
            "/auth/send-code",
            json={"email": email, "code_type": "password_reset"},
            headers={"X-Forwarded-For": ip_address},
            name="send_code_password_reset",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 429:
                response.failure("Rate limit exceeded")
            elif response.status_code == 500:
                response.failure("Email send error")
            elif response.status_code < 500:
                response.failure(f"Expected 200, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(1)
    def verify_code_invalid(self):
        if not self.csrf_token:
            self.get_csrf_token()
        email = generate_email()
        ip_address = f"127.0.0.{random.randint(1, 255)}"
        with self.client.post(
            "/auth/verify-code",
            json={"email": email, "code": "000000", "code_type": "email_verification"},
            headers={"X-Forwarded-For": ip_address},
            name="verify_code_invalid",
            catch_response=True,
        ) as response:
            if response.status_code == 400:
                response.success()
            elif response.status_code < 500:
                response.failure(f"Expected 400, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")


class RegistrationFlowTasks(TaskSet):
    def on_start(self):
        self.csrf_token = None
        self.email = None
        self.password = None
        self.ip_address = f"127.0.0.{random.randint(1, 255)}"
        self.get_csrf_token()

    def get_csrf_token(self):
        with self.client.get("/auth/csrf", name="get_csrf_token", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get("token")
                if self.csrf_token:
                    self.client.headers.update({"X-CSRFToken": self.csrf_token})
                response.success()
            else:
                response.failure(f"Expected 200, got {response.status_code}")

    @task(1)
    def full_registration_flow(self):
        if not self.csrf_token:
            self.get_csrf_token()

        self.email = generate_email()
        self.password = generate_password()

        with self.client.post(
            "/auth/send-code",
            json={"email": self.email, "code_type": "email_verification"},
            headers={"X-Forwarded-For": self.ip_address},
            name="send_code_registration",
            catch_response=True,
        ) as send_response:
            if send_response.status_code == 200:
                send_response.success()
                time.sleep(0.5)

                code = get_verification_code(self.email, self.ip_address, "email_verification")

                if code:
                    with self.client.post(
                        "/auth/verify-code",
                        json={
                            "email": self.email,
                            "code": code,
                            "code_type": "email_verification",
                        },
                        headers={"X-Forwarded-For": self.ip_address},
                        name="verify_code_registration",
                        catch_response=True,
                    ) as verify_response:
                        if verify_response.status_code == 200:
                            verify_response.success()

                            with self.client.post(
                                "/auth/register",
                                json={
                                    "first_name": "Test",
                                    "last_name": "User",
                                    "email": self.email,
                                    "password": self.password,
                                    "password2": self.password,
                                },
                                headers={"X-Forwarded-For": self.ip_address},
                                name="register",
                                catch_response=True,
                            ) as register_response:
                                if register_response.status_code == 201:
                                    register_response.success()
                                elif register_response.status_code == 400:
                                    register_response.failure("Registration validation error")
                                else:
                                    register_response.failure(
                                        f"Expected 201, got {register_response.status_code}"
                                    )
                        elif verify_response.status_code == 400:
                            verify_response.failure("Code verification failed")
                        else:
                            verify_response.failure(
                                f"Expected 200, got {verify_response.status_code}"
                            )
                else:
                    send_response.failure("Could not retrieve verification code from cache")
            elif send_response.status_code == 429:
                send_response.failure("Rate limit exceeded")
            elif send_response.status_code == 500:
                send_response.failure("Email send error")
            else:
                send_response.failure(f"Expected 200, got {send_response.status_code}")

    @task(1)
    def register_without_verification(self):
        if not self.csrf_token:
            self.get_csrf_token()

        email = generate_email()
        password = generate_password()

        with self.client.post(
            "/auth/register",
            json={
                "first_name": "Test",
                "last_name": "User",
                "email": email,
                "password": password,
                "password2": password,
            },
            name="register_without_verification",
            catch_response=True,
        ) as response:
            if response.status_code == 400:
                response.success()
            elif response.status_code < 500:
                response.failure(f"Expected 400, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(1)
    def register_passwords_mismatch(self):
        if not self.csrf_token:
            self.get_csrf_token()

        email = generate_email()
        self.ip_address = f"127.0.0.{random.randint(1, 255)}"

        with self.client.post(
            "/auth/send-code",
            json={"email": email, "code_type": "email_verification"},
            headers={"X-Forwarded-For": self.ip_address},
            name="send_code_mismatch",
            catch_response=True,
        ) as send_response:
            if send_response.status_code == 200:
                send_response.success()
                time.sleep(0.5)

                code = get_verification_code(email, self.ip_address, "email_verification")

                if code:
                    with self.client.post(
                        "/auth/verify-code",
                        json={
                            "email": email,
                            "code": code,
                            "code_type": "email_verification",
                        },
                        headers={"X-Forwarded-For": self.ip_address},
                        name="verify_code_mismatch",
                        catch_response=True,
                    ) as verify_response:
                        if verify_response.status_code == 200:
                            verify_response.success()

                            with self.client.post(
                                "/auth/register",
                                json={
                                    "first_name": "Test",
                                    "last_name": "User",
                                    "email": email,
                                    "password": "Password123",
                                    "password2": "Password456",
                                },
                                headers={"X-Forwarded-For": self.ip_address},
                                name="register_passwords_mismatch",
                                catch_response=True,
                            ) as register_response:
                                if register_response.status_code == 400:
                                    register_response.success()
                                else:
                                    register_response.failure(
                                        f"Expected 400, got {register_response.status_code}"
                                    )


class LoginTasks(TaskSet):
    def on_start(self):
        self.csrf_token = None
        self.email = None
        self.password = None
        self.ip_address = f"127.0.0.{random.randint(1, 255)}"
        self.get_csrf_token()

    def get_csrf_token(self):
        with self.client.get("/auth/csrf", name="get_csrf_token", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get("token")
                if self.csrf_token:
                    self.client.headers.update({"X-CSRFToken": self.csrf_token})
                response.success()
            else:
                response.failure(f"Expected 200, got {response.status_code}")

    @task(3)
    def login_success(self):
        if not self.csrf_token:
            self.get_csrf_token()

        if not self.email or not self.password:
            self.email = generate_email()
            self.password = generate_password()
            self.ip_address = f"127.0.0.{random.randint(1, 255)}"

            with self.client.post(
                "/auth/send-code",
                json={"email": self.email, "code_type": "email_verification"},
                headers={"X-Forwarded-For": self.ip_address},
                name="send_code_for_login",
                catch_response=True,
            ) as send_response:
                if send_response.status_code == 200:
                    send_response.success()
                    time.sleep(0.5)

                    code = get_verification_code(self.email, self.ip_address, "email_verification")

                    if code:
                        with self.client.post(
                            "/auth/verify-code",
                            json={
                                "email": self.email,
                                "code": code,
                                "code_type": "email_verification",
                            },
                            headers={"X-Forwarded-For": self.ip_address},
                            name="verify_code_for_login",
                            catch_response=True,
                        ) as verify_response:
                            if verify_response.status_code == 200:
                                verify_response.success()

                                with self.client.post(
                                    "/auth/register",
                                    json={
                                        "first_name": "Test",
                                        "last_name": "User",
                                        "email": self.email,
                                        "password": self.password,
                                        "password2": self.password,
                                    },
                                    headers={"X-Forwarded-For": self.ip_address},
                                    name="register_for_login",
                                    catch_response=True,
                                ) as register_response:
                                    if register_response.status_code == 201:
                                        register_response.success()

        with self.client.post(
            "/auth/login",
            json={"email": self.email, "password": self.password},
            headers={"X-Forwarded-For": self.ip_address},
            name="login",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 401:
                response.failure("Invalid credentials")
            elif response.status_code == 403:
                lockout_data = response.json() if response.content else {}
                if lockout_data.get("code") == "auth.login_lockout":
                    response.failure(f"Account locked: {lockout_data.get('time')} minutes")
                else:
                    response.failure("Forbidden")
            elif response.status_code < 500:
                response.failure(f"Expected 200, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(2)
    def login_invalid_credentials(self):
        if not self.csrf_token:
            self.get_csrf_token()

        email = generate_email()
        ip_address = f"127.0.0.{random.randint(1, 255)}"

        with self.client.post(
            "/auth/login",
            json={"email": email, "password": "wrongpassword"},
            headers={"X-Forwarded-For": ip_address},
            name="login_invalid",
            catch_response=True,
        ) as response:
            if response.status_code == 401:
                response.success()
            elif response.status_code == 403:
                lockout_data = response.json() if response.content else {}
                if lockout_data.get("code") == "auth.login_lockout":
                    response.success()
                else:
                    response.failure("Unexpected 403")
            elif response.status_code < 500:
                response.failure(f"Expected 401 or 403, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(1)
    def login_lockout_test(self):
        if not self.csrf_token:
            self.get_csrf_token()

        email = generate_email()
        ip_address = f"127.0.0.{random.randint(1, 255)}"

        for attempt in range(4):
            with self.client.post(
                "/auth/login",
                json={"email": email, "password": "wrongpassword"},
                headers={"X-Forwarded-For": ip_address},
                name="login_lockout_attempt",
                catch_response=True,
            ) as response:
                if attempt < 3:
                    if response.status_code == 401:
                        response.success()
                    elif response.status_code == 403:
                        response.success()
                    else:
                        response.failure(f"Expected 401 or 403, got {response.status_code}")
                else:
                    if response.status_code == 403:
                        lockout_data = response.json() if response.content else {}
                        if lockout_data.get("code") == "auth.login_lockout":
                            response.success()
                        else:
                            response.failure("Lockout without proper response")
                    else:
                        response.failure(f"Expected 403 after 3 attempts, got {response.status_code}")


class AuthenticatedUserTasks(TaskSet):
    def on_start(self):
        self.csrf_token = None
        self.email = None
        self.password = None
        self.ip_address = f"127.0.0.{random.randint(1, 255)}"
        self.get_csrf_token()
        self.register_and_login()

    def get_csrf_token(self):
        with self.client.get("/auth/csrf", name="get_csrf_token", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get("token")
                if self.csrf_token:
                    self.client.headers.update({"X-CSRFToken": self.csrf_token})
                response.success()

    def register_and_login(self):
        self.email = generate_email()
        self.password = generate_password()

        with self.client.post(
            "/auth/send-code",
            json={"email": self.email, "code_type": "email_verification"},
            headers={"X-Forwarded-For": self.ip_address},
            catch_response=True,
        ) as send_response:
            if send_response.status_code == 200:
                time.sleep(0.5)
                code = get_verification_code(self.email, self.ip_address, "email_verification")

                if code:
                    with self.client.post(
                        "/auth/verify-code",
                        json={
                            "email": self.email,
                            "code": code,
                            "code_type": "email_verification",
                        },
                        headers={"X-Forwarded-For": self.ip_address},
                        catch_response=True,
                    ) as verify_response:
                        if verify_response.status_code == 200:
                            with self.client.post(
                                "/auth/register",
                                json={
                                    "first_name": "Test",
                                    "last_name": "User",
                                    "email": self.email,
                                    "password": self.password,
                                    "password2": self.password,
                                },
                                headers={"X-Forwarded-For": self.ip_address},
                                catch_response=True,
                            ) as register_response:
                                if register_response.status_code == 201:
                                    with self.client.post(
                                        "/auth/login",
                                        json={"email": self.email, "password": self.password},
                                        headers={"X-Forwarded-For": self.ip_address},
                                        catch_response=True,
                                    ):
                                        pass

    @task(5)
    def get_userinfo(self):
        if not self.csrf_token:
            self.get_csrf_token()

        with self.client.get("/auth/userinfo", name="get_userinfo", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                if "email" in data and "first_name" in data:
                    response.success()
                else:
                    response.failure("Invalid userinfo response")
            elif response.status_code == 403:
                response.failure("Not authenticated")
            elif response.status_code < 500:
                response.failure(f"Expected 200, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(2)
    def logout(self):
        if not self.csrf_token:
            self.get_csrf_token()

        with self.client.post("/auth/logout", name="logout", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code < 500:
                response.failure(f"Expected 200, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")


class PasswordResetFlowTasks(TaskSet):
    def on_start(self):
        self.csrf_token = None
        self.email = None
        self.password = None
        self.ip_address = f"127.0.0.{random.randint(1, 255)}"
        self.get_csrf_token()
        self.create_user()

    def get_csrf_token(self):
        with self.client.get("/auth/csrf", name="get_csrf_token", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get("token")
                if self.csrf_token:
                    self.client.headers.update({"X-CSRFToken": self.csrf_token})
                response.success()

    def create_user(self):
        self.email = generate_email()
        self.password = generate_password()

        with self.client.post(
            "/auth/send-code",
            json={"email": self.email, "code_type": "email_verification"},
            headers={"X-Forwarded-For": self.ip_address},
            catch_response=True,
        ) as send_response:
            if send_response.status_code == 200:
                time.sleep(0.5)
                code = get_verification_code(self.email, self.ip_address, "email_verification")

                if code:
                    with self.client.post(
                        "/auth/verify-code",
                        json={
                            "email": self.email,
                            "code": code,
                            "code_type": "email_verification",
                        },
                        headers={"X-Forwarded-For": self.ip_address},
                        catch_response=True,
                    ) as verify_response:
                        if verify_response.status_code == 200:
                            with self.client.post(
                                "/auth/register",
                                json={
                                    "first_name": "Test",
                                    "last_name": "User",
                                    "email": self.email,
                                    "password": self.password,
                                    "password2": self.password,
                                },
                                headers={"X-Forwarded-For": self.ip_address},
                                catch_response=True,
                            ):
                                pass

    @task(1)
    def full_password_reset_flow(self):
        if not self.csrf_token:
            self.get_csrf_token()

        new_password = generate_password()
        ip_address = f"127.0.0.{random.randint(1, 255)}"

        with self.client.post(
            "/auth/check-email",
            json={"email": self.email},
            name="check_email_reset",
            catch_response=True,
        ) as check_response:
            if check_response.status_code in (200, 404):
                check_response.success()

        with self.client.post(
            "/auth/send-code",
            json={"email": self.email, "code_type": "password_reset"},
            headers={"X-Forwarded-For": ip_address},
            name="send_code_reset",
            catch_response=True,
        ) as send_response:
            if send_response.status_code == 200:
                send_response.success()
                time.sleep(0.5)

                code = get_verification_code(self.email, ip_address, "password_reset")

                if code:
                    with self.client.post(
                        "/auth/verify-code",
                        json={
                            "email": self.email,
                            "code": code,
                            "code_type": "password_reset",
                        },
                        headers={"X-Forwarded-For": ip_address},
                        name="verify_code_reset",
                        catch_response=True,
                    ) as verify_response:
                        if verify_response.status_code == 200:
                            verify_response.success()

                            with self.client.post(
                                "/auth/password-reset-confirm",
                                json={
                                    "email": self.email,
                                    "password": new_password,
                                    "password2": new_password,
                                },
                                headers={"X-Forwarded-For": ip_address},
                                name="password_reset_confirm",
                                catch_response=True,
                            ) as confirm_response:
                                if confirm_response.status_code == 200:
                                    confirm_response.success()
                                    self.password = new_password
                                elif confirm_response.status_code == 400:
                                    confirm_response.failure("Password reset validation error")
                                else:
                                    confirm_response.failure(
                                        f"Expected 200, got {confirm_response.status_code}"
                                    )
                        elif verify_response.status_code == 400:
                            verify_response.failure("Code verification failed")
                        else:
                            verify_response.failure(
                                f"Expected 200, got {verify_response.status_code}"
                            )
                else:
                    send_response.failure("Could not retrieve verification code from cache")
            elif send_response.status_code == 429:
                send_response.failure("Rate limit exceeded")
            elif send_response.status_code == 500:
                send_response.failure("Email send error")
            else:
                send_response.failure(f"Expected 200, got {send_response.status_code}")

    @task(1)
    def password_reset_without_verification(self):
        if not self.csrf_token:
            self.get_csrf_token()

        new_password = generate_password()
        ip_address = f"127.0.0.{random.randint(1, 255)}"

        with self.client.post(
            "/auth/password-reset-confirm",
            json={
                "email": self.email,
                "password": new_password,
                "password2": new_password,
            },
            headers={"X-Forwarded-For": ip_address},
            name="password_reset_without_verification",
            catch_response=True,
        ) as response:
            if response.status_code == 400:
                response.success()
            elif response.status_code < 500:
                response.failure(f"Expected 400, got {response.status_code}")
            else:
                response.failure(f"Server error: {response.status_code}")

    @task(1)
    def password_reset_passwords_mismatch(self):
        if not self.csrf_token:
            self.get_csrf_token()

        ip_address = f"127.0.0.{random.randint(1, 255)}"

        with self.client.post(
            "/auth/send-code",
            json={"email": self.email, "code_type": "password_reset"},
            headers={"X-Forwarded-For": ip_address},
            name="send_code_mismatch_reset",
            catch_response=True,
        ) as send_response:
            if send_response.status_code == 200:
                send_response.success()
                time.sleep(0.5)

                code = get_verification_code(self.email, ip_address, "password_reset")

                if code:
                    with self.client.post(
                        "/auth/verify-code",
                        json={
                            "email": self.email,
                            "code": code,
                            "code_type": "password_reset",
                        },
                        headers={"X-Forwarded-For": ip_address},
                        name="verify_code_mismatch_reset",
                        catch_response=True,
                    ) as verify_response:
                        if verify_response.status_code == 200:
                            verify_response.success()

                            with self.client.post(
                                "/auth/password-reset-confirm",
                                json={
                                    "email": self.email,
                                    "password": "NewPass123",
                                    "password2": "NewPass456",
                                },
                                headers={"X-Forwarded-For": ip_address},
                                name="password_reset_passwords_mismatch",
                                catch_response=True,
                            ) as confirm_response:
                                if confirm_response.status_code == 400:
                                    confirm_response.success()
                                else:
                                    confirm_response.failure(
                                        f"Expected 400, got {confirm_response.status_code}"
                                    )


class AnonymousUser(HttpUser):
    tasks = [AnonymousUserTasks]
    wait_time = between(1, 3)


class RegistrationUser(HttpUser):
    tasks = [RegistrationFlowTasks]
    wait_time = between(2, 5)


class LoginUser(HttpUser):
    tasks = [LoginTasks]
    wait_time = between(1, 3)


class AuthenticatedUser(HttpUser):
    tasks = [AuthenticatedUserTasks]
    wait_time = between(1, 2)


class PasswordResetUser(HttpUser):
    tasks = [PasswordResetFlowTasks]
    wait_time = between(3, 7)
