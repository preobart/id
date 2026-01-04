from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.test import TestCase
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from id.managers import EmailVerificationManager
from id.serializers import (
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    UserRegistrationSerializer,
)


User = get_user_model()


class UserRegistrationSerializerTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.existing_user = User.objects.create_user(
            username="existing", email="existing@example.com", password="password123"
        )

    def test_valid_registration(self):
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
        self.assertTrue(user.check_password("StrongPass123"))

    def test_password_mismatch(self):
        data = {
            "first_name": "User",
            "last_name": "One",
            "email": "user1@example.com",
            "password": "password123",
            "password2": "different123",
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)
        self.assertIn("Passwords do not match", str(serializer.errors["password"]))

    def test_invalid_passwords(self):
        invalid_passwords = [
            ("123", ["This password is too short. It must contain at least 8 characters."]),
            ("12345678", ["This password is entirely numeric."]),
        ]
        for pwd, expected_errors in invalid_passwords:
            with self.subTest(pwd=pwd):
                data = {
                    "first_name": "User",
                    "last_name": "Test",
                    "email": f"user_{pwd}@example.com",
                    "password": pwd,
                    "password2": pwd,
                }
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn("password", serializer.errors)

                errors = [str(e) for e in serializer.errors["password"]]
                for expected_error in expected_errors:
                    self.assertIn(expected_error, errors)

    def test_non_unique_fields(self):
        non_unique_data = [
            ("unique_email@example.com", "email"),
        ]
        for email, field in non_unique_data:
            with self.subTest(field=field):
                data = {
                    "first_name": "User",
                    "last_name": "Test",
                    "email": email,
                    "password": "StrongPass123",
                    "password2": "StrongPass123",
                }
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn(field, serializer.errors)
                self.assertIsInstance(serializer.errors[field], list)


class PasswordResetSerializerTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="resetuser", email="reset@example.com", password="password123"
        )

    def test_valid_email(self):
        serializer = PasswordResetSerializer(data={"email": self.user.email})
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_invalid_email(self):
        serializer = PasswordResetSerializer(data={"email": "notfound@example.com"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)
        self.assertIsInstance(serializer.errors["email"], list)


class PasswordResetConfirmSerializerTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="confirmuser", email="confirm@example.com", password="password123"
        )
        cls.uid = urlsafe_base64_encode(force_bytes(cls.user.pk))
        cls.token = default_token_generator.make_token(cls.user)

    def test_valid_token(self):
        serializer = PasswordResetConfirmSerializer(
            data={"email": self.user.email, "password": "NewStrongPass123", "password2": "NewStrongPass123"}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewStrongPass123"))

    def test_invalid_uid_or_token(self):
        test_cases = [
            {"email": "invalid@example.com", "password": "NewPass123", "password2": "NewPass123"},
            {"email": "nonexistent@example.com", "password": "NewPass123", "password2": "NewPass123"},
        ]
        for data in test_cases:
            with self.subTest(data=data):
                serializer = PasswordResetConfirmSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn("email", serializer.errors)
                self.assertIsInstance(serializer.errors["email"], list)

    def test_short_password(self):
        serializer = PasswordResetConfirmSerializer(
            data={"email": self.user.email, "password": "123", "password2": "123"}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)
        self.assertTrue(len(serializer.errors["password"]) > 0)
