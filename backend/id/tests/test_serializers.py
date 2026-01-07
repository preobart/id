from django.contrib.auth import get_user_model

from rest_framework.test import APITestCase

from id.managers import VerificationManager
from id.serializers import (
    CodeSendSerializer,
    CodeVerifySerializer,
    PasswordResetConfirmSerializer,
    RegistrationSerializer,
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
        serializer = RegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)
        self.assertIn("Email must be verified before registration", str(serializer.errors["email"]))

    def test_valid_registration_with_verified_email(self):
        email = "newuser@example.com"
        ip_address = "127.0.0.1"
        manager = VerificationManager(email, ip_address, "email_verification")
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
        from rest_framework.test import APIRequestFactory
        factory = APIRequestFactory()
        request = factory.post("/")
        serializer = RegistrationSerializer(data=data, context={"request": request})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        user = serializer.save()
        self.assertEqual(user.email, email)
        self.assertEqual(user.username, email)


class CodeSendSerializerTest(APITestCase):
    def test_code_type_required(self):
        serializer = CodeSendSerializer(data={"email": "test@example.com"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("code_type", serializer.errors)

    def test_valid_data(self):
        serializer = CodeSendSerializer(data={"email": "test@example.com", "code_type": "email_verification"})
        self.assertTrue(serializer.is_valid(), serializer.errors)


class CodeVerifySerializerTest(APITestCase):
    def test_code_must_be_digits(self):
        serializer = CodeVerifySerializer(data={"email": "test@example.com", "code": "abc123", "code_type": "email_verification"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("code", serializer.errors)
        self.assertIn("Code must contain only digits", str(serializer.errors["code"]))

    def test_valid_digit_code(self):
        serializer = CodeVerifySerializer(data={"email": "test@example.com", "code": "123456", "code_type": "email_verification"})
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
