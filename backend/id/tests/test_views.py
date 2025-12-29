from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from id.utils import generate_and_store_code, is_email_verified, mark_email_verified, verify_code


User = get_user_model()


class ViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

        self.register_url = reverse("register")
        self.login_url = reverse("login")
        self.logout_url = reverse("logout")
        self.user_url = reverse("userinfo")
        self.password_reset_url = reverse("password-reset")
        self.password_reset_confirm_url = reverse("password-reset-confirm")
        self.verify_email_request_url = reverse("verify-email-request")
        self.verify_email_confirm_url = reverse("verify-email-confirm")

        self.user = User.objects.create_user(
            username="user", email="user@example.com", password="password-123"
        )

    @patch("id.views.check_smartcaptcha", return_value=True)
    def test_register_user_successfully(self, mock_captcha):
        email = "newuser@example.com"
        code = generate_and_store_code(email)
        verify_code(email, code)
        mark_email_verified(email)

        data = {
            "first_name": "New",
            "last_name": "User",
            "email": email,
            "password": "newpassword123",
            "password2": "newpassword123",
            "token": "captcha_token",
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("user", response.data)
        self.assertFalse(is_email_verified(email))

    @patch("id.views.check_smartcaptcha", return_value=True)
    def test_register_user_passwords_do_not_match(self, mock_captcha):
        email = "user1@example.com"
        code = generate_and_store_code(email)
        verify_code(email, code)
        mark_email_verified(email)

        data = {
            "first_name": "User",
            "last_name": "One",
            "email": email,
            "password": "password1",
            "password2": "password2",
            "token": "captcha_token",
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)

    @patch("id.views.check_smartcaptcha", return_value=True)
    def test_register_user_without_verified_email(self, mock_captcha):
        data = {
            "first_name": "User",
            "last_name": "Two",
            "email": "unverified@example.com",
            "password": "password123",
            "password2": "password123",
            "token": "captcha_token",
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)
        self.assertIn("Email must be verified", str(response.data["email"]))

    @patch("id.views.check_smartcaptcha", return_value=False)
    def test_register_user_invalid_captcha(self, mock_captcha):
        email = "test@example.com"
        code = generate_and_store_code(email)
        verify_code(email, code)
        mark_email_verified(email)

        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": email,
            "password": "password123",
            "password2": "password123",
            "token": "invalid_captcha",
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("token", response.data)

    def test_login_successful(self):
        data = {"username": "user2", "password": "password-123"}
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("user", response.data)

    def test_login_invalid_credentials(self):
        data = {"username": "user", "password": "wrongpass"}
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

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
        self.assertEqual(response.data["username"], self.user.username)

    def test_get_user_data_unauthenticated(self):
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_password_reset_email_sent(self):
        data = {"email": self.user.email}
        response = self.client.post(self.password_reset_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Password reset email has been sent", response.data["detail"])

    def test_password_reset_email_invalid(self):
        data = {"email": "invalid@example.com"}
        response = self.client.post(self.password_reset_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_confirm_success(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)

        data = {
            "uid": uid,
            "token": token,
            "password": "newpass123",
        }
        response = self.client.post(self.password_reset_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Password has been reset", response.data["detail"])

    def test_password_reset_confirm_invalid(self):
        data = {
            "uid": "baduid",
            "token": "badtoken",
            "password": "newpass123",
        }
        response = self.client.post(self.password_reset_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class EmailVerificationTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.verify_email_request_url = reverse("verify-email-request")
        self.verify_email_confirm_url = reverse("verify-email-confirm")
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_verify_email_request_success(self):
        data = {"email": "newuser@example.com"}
        response = self.client.post(self.verify_email_request_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("detail", response.data)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Email Verification Code")
        self.assertIn("Your verification code is:", mail.outbox[0].body)

    def test_verify_email_request_existing_user(self):
        User.objects.create_user(
            username="existing", email="existing@example.com", password="password123"
        )
        data = {"email": "existing@example.com"}
        response = self.client.post(self.verify_email_request_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_verify_email_request_invalid_email(self):
        data = {"email": "invalid-email"}
        response = self.client.post(self.verify_email_request_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_verify_email_confirm_success(self):
        email = "test@example.com"
        code = generate_and_store_code(email)

        data = {"email": email, "code": str(code)}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["verified"])
        self.assertTrue(is_email_verified(email))

    def test_verify_email_confirm_invalid_code(self):
        email = "test@example.com"
        generate_and_store_code(email)

        data = {"email": email, "code": "000000"}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)
        self.assertFalse(is_email_verified(email))

    def test_verify_email_confirm_expired_code(self):
        email = "test@example.com"
        code = generate_and_store_code(email)

        cache.delete(f"otp_device:{email}:code")

        data = {"email": email, "code": str(code)}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_max_attempts(self):
        email = "test@example.com"
        code = generate_and_store_code(email)

        for _ in range(3):
            data = {"email": email, "code": "000000"}
            response = self.client.post(self.verify_email_confirm_url, data)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = {"email": email, "code": str(code)}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_invalid_email_format(self):
        data = {"email": "invalid-email", "code": "123456"}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_verify_email_confirm_invalid_code_format(self):
        data = {"email": "test@example.com", "code": "abc123"}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_code_too_short(self):
        data = {"email": "test@example.com", "code": "12345"}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)

    def test_verify_email_confirm_code_too_long(self):
        data = {"email": "test@example.com", "code": "1234567"}
        response = self.client.post(self.verify_email_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)
