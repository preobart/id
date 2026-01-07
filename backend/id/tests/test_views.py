from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache, caches
from django.urls import reverse

from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from id.managers import VerificationManager


User = get_user_model()


class ViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse("register")
        self.login_url = reverse("login")
        self.logout_url = reverse("logout")
        self.user_url = reverse("userinfo")
        self.password_reset_url = reverse("send-code")
        self.password_reset_verify_url = reverse("verify-code")
        self.password_reset_confirm_url = reverse("password-reset-confirm")
        self.verify_email_request_url = reverse("check-email")
        self.verify_email_confirm_url = reverse("verify-code")

        self.user = User.objects.create_user(
            username="user", email="user@example.com", password="password-123"
        )
        self.ip_address = "127.0.0.1"

    def test_register_user_successfully(self):
        email = "newuser@example.com"
        manager = VerificationManager(email, self.ip_address, "email_verification")
        code = manager.generate_and_store_code()
        manager.verify_code(code)
        manager.mark_verified()

        data = {
            "first_name": "New",
            "last_name": "User",
            "email": email,
            "password": "newpassword123",
            "password2": "newpassword123",
            "token": "captcha_token",
        }
        response = self.client.post(self.register_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["email"], email)
        self.assertFalse(VerificationManager(email, self.ip_address, "email_verification").is_verified())

    def test_register_user_passwords_do_not_match(self):
        email = "user1@example.com"
        manager = VerificationManager(email, self.ip_address, "email_verification")
        code = manager.generate_and_store_code()
        manager.verify_code(code)
        manager.mark_verified()

        data = {
            "first_name": "User",
            "last_name": "One",
            "email": email,
            "password": "password1",
            "password2": "password2",
            "token": "captcha_token",
        }
        response = self.client.post(self.register_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)

    def test_register_user_without_verified_email(self):
        data = {
            "first_name": "User",
            "last_name": "Two",
            "email": "unverified@example.com",
            "password": "password123",
            "password2": "password123",
            "token": "captcha_token",
        }
        response = self.client.post(self.register_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)
        self.assertIn("Email must be verified", str(response.data["email"]))

    def test_register_user_successful_without_captcha(self):
        import uuid
        email = f"testcaptcha{uuid.uuid4().hex[:8]}@example.com"
        manager = VerificationManager(email, self.ip_address, "email_verification")
        code = manager.generate_and_store_code()
        manager.verify_code(code)
        manager.mark_verified()

        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": email,
            "password": "StrongPass123!",
            "password2": "StrongPass123!",
        }
        response = self.client.post(self.register_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertEqual(response.data["email"], email)

    def test_login_successful(self):
        login_user = User.objects.create_user(
            username="loginuser@example.com", email="loginuser@example.com", password="password-123"
        )
        data = {"email": login_user.email, "password": "password-123"}
        response = self.client.post(self.login_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("user", response.data)

    def test_login_invalid_credentials(self):
        data = {"email": self.user.email, "password": "wrongpass"}
        response = self.client.post(self.login_url, data, REMOTE_ADDR=self.ip_address)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    def test_logout_authenticated(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Logged out")

    def test_logout_unauthenticated(self):
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Logged out")

    def test_get_user_data_authenticated(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], self.user.email)

    def test_get_user_data_unauthenticated(self):
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_password_reset_email_sent(self):
        data = {"email": self.user.email, "code_type": "password_reset"}
        response = self.client.post(self.password_reset_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Verification code has been sent", response.data["detail"])

    def test_password_reset_email_invalid(self):
        data = {"email": "invalid@example.com", "code_type": "password_reset"}
        response = self.client.post(self.password_reset_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

    def test_password_reset_verify_success(self):
        email = self.user.email
        manager = VerificationManager(email, self.ip_address, "password_reset")
        code = manager.generate_and_store_code()

        data = {"email": email, "code": str(code), "code_type": "password_reset"}
        response = self.client.post(self.password_reset_verify_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["verified"])
        self.assertTrue(VerificationManager(email, self.ip_address, "password_reset").is_verified())

    def test_password_reset_verify_invalid_code(self):
        email = self.user.email
        manager = VerificationManager(email, self.ip_address, "password_reset")
        manager.generate_and_store_code()

        data = {"email": email, "code": "000000", "code_type": "password_reset"}
        response = self.client.post(self.password_reset_verify_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_password_reset_verify_expired_code(self):
        email = self.user.email
        manager = VerificationManager(email, self.ip_address, "password_reset")
        code = manager.generate_and_store_code()

        caches["email_verification"].delete(f"password_reset:code:{email}:{self.ip_address}")

        data = {"email": email, "code": str(code), "code_type": "password_reset"}
        response = self.client.post(self.password_reset_verify_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_password_reset_confirm_unverified_email(self):
        email = self.user.email
        data = {
            "email": email,
            "password": "newpass123",
            "password2": "newpass123",
        }
        response = self.client.post(self.password_reset_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)
        self.assertIn("Email must be verified", str(response.data["email"]))

    def test_password_reset_confirm_success(self):
        email = self.user.email
        manager = VerificationManager(email, self.ip_address, "password_reset")
        code = manager.generate_and_store_code()
        manager.verify_code(code)
        manager.mark_verified()

        data = {
            "email": email,
            "password": "newpass123",
            "password2": "newpass123",
        }
        response = self.client.post(self.password_reset_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Password has been reset", response.data["detail"])

    def test_password_reset_confirm_invalid(self):
        data = {
            "email": "nonexistent@example.com",
            "password": "newpass123",
            "password2": "newpass123",
        }
        response = self.client.post(self.password_reset_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class EmailVerificationTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.check_email_url = reverse("check-email")
        self.send_code_url = reverse("send-code")
        self.verify_email_confirm_url = reverse("verify-code")
        cache.clear()
        self.ip_address = "127.0.0.1"

    def tearDown(self):
        cache.clear()

    def test_verify_email_request_success(self):
        data = {"email": "newuser@example.com", "code_type": "email_verification"}
        response = self.client.post(self.send_code_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("detail", response.data)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Verification Code")
        self.assertIn("Your verification code is:", mail.outbox[0].body)

    def test_verify_email_request_existing_user(self):
        User.objects.create_user(
            username="existing", email="existing@example.com", password="password123"
        )
        response = self.client.get(self.check_email_url, {"email": "existing@example.com"}, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["action"], "login")

    def test_verify_email_request_invalid_email(self):
        data = {"email": "invalid-email", "code_type": "email_verification"}
        response = self.client.post(self.send_code_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_verify_email_confirm_success(self):
        email = "test@example.com"
        manager = VerificationManager(email, self.ip_address, "email_verification")
        code = manager.generate_and_store_code()

        data = {"email": email, "code": str(code), "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["verified"])
        self.assertTrue(VerificationManager(email, self.ip_address, "email_verification").is_verified())

    def test_verify_email_confirm_invalid_code(self):
        email = "test@example.com"
        manager = VerificationManager(email, self.ip_address, "email_verification")
        manager.generate_and_store_code()

        data = {"email": email, "code": "000000", "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)
        self.assertFalse(VerificationManager(email, self.ip_address, "email_verification").is_verified())

    def test_verify_email_confirm_expired_code(self):
        email = "test@example.com"
        manager = VerificationManager(email, self.ip_address, "email_verification")
        code = manager.generate_and_store_code()

        caches["email_verification"].delete(f"email_verification:code:{email}:{self.ip_address}")

        data = {"email": email, "code": str(code), "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_max_attempts(self):
        email = "test@example.com"
        manager = VerificationManager(email, self.ip_address, "email_verification")
        code = manager.generate_and_store_code()

        for _ in range(3):
            data = {"email": email, "code": "000000", "code_type": "email_verification"}
            response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = {"email": email, "code": str(code), "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_invalid_email_format(self):
        data = {"email": "invalid-email", "code": "123456", "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_verify_email_confirm_invalid_code_format(self):
        data = {"email": "test@example.com", "code": "abc123", "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_code_too_short(self):
        data = {"email": "test@example.com", "code": "12345", "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_code_too_long(self):
        data = {"email": "test@example.com", "code": "1234567", "code_type": "email_verification"}
        response = self.client.post(self.verify_email_confirm_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)
