from django.contrib.auth import get_user_model

from rest_framework.test import APITestCase

from id.managers import EmailVerificationManager
from id.serializers import (
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    PasswordResetVerifySerializer,
    UserRegistrationSerializer,
)


User = get_user_model()


class UserRegistrationSerializerTest(APITestCase):
    def test_email_verification_required(self):
        email = "newuser@example.com"
        data = {
            "first_name": "New",
            "last_name": "User",
            "email": email,
            "password": "StrongPass123",
            "password2": "StrongPass123",
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)
        self.assertIn("Email must be verified before registration", str(serializer.errors["email"]))

    def test_valid_registration_with_verified_email(self):
        email = "newuser@example.com"
        manager = EmailVerificationManager(email, "")
        code = manager.generate_and_store_code()
        manager.verify_code(code)
        manager.mark_verified()

        data = {
            "first_name": "New",
            "last_name": "User",
            "email": email,
            "password": "StrongPass123",
            "password2": "StrongPass123",
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        user = serializer.save()
        self.assertEqual(user.email, email)
        self.assertEqual(user.username, email)


class PasswordResetSerializerTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="resetuser", email="reset@example.com", password="password123"
        )

    def test_valid_email(self):
        serializer = PasswordResetSerializer(data={"email": self.user.email})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["email"], self.user.email)
        self.assertEqual(serializer.user, self.user)

    def test_invalid_email(self):
        serializer = PasswordResetSerializer(data={"email": "notfound@example.com"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)
        self.assertIn("User with this email does not exist", str(serializer.errors["email"]))


class PasswordResetVerifySerializerTest(APITestCase):
    def test_code_must_be_digits(self):
        serializer = PasswordResetVerifySerializer(data={"email": "test@example.com", "code": "abc123"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("code", serializer.errors)
        self.assertIn("Code must contain only digits", str(serializer.errors["code"]))

    def test_valid_digit_code(self):
        serializer = PasswordResetVerifySerializer(data={"email": "test@example.com", "code": "123456"})
        self.assertTrue(serializer.is_valid(), serializer.errors)


class PasswordResetConfirmSerializerTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="confirmuser", email="confirm@example.com", password="password123"
        )

    def test_user_must_exist(self):
        serializer = PasswordResetConfirmSerializer(
            data={"email": "nonexistent@example.com", "password": "NewPass123", "password2": "NewPass123"}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)
        self.assertIn("User with this email does not exist", str(serializer.errors["email"]))

    def test_password_reset_success(self):
        serializer = PasswordResetConfirmSerializer(
            data={"email": self.user.email, "password": "NewStrongPass123", "password2": "NewStrongPass123"}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewStrongPass123"))
