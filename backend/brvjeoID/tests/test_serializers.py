from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.test import TestCase
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from core.authentication.serializers import (
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
        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "StrongPass123",
            "password2": "StrongPass123",
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        user = serializer.save()
        self.assertEqual(user.email, "newuser@example.com")
        self.assertTrue(user.check_password("StrongPass123"))

    def test_password_mismatch(self):
        data = {
            "username": "user1",
            "email": "user1@example.com",
            "password": "password123",
            "password2": "different123",
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    def test_invalid_passwords(self):
        invalid_passwords = [
            ("123", "too short"),
            ("12345678", "entirely numeric"),
        ]
        for pwd, desc in invalid_passwords:
            with self.subTest(desc=desc):
                data = {"username": f"user_{desc}", "email": f"{desc}@example.com", "password": pwd, "password2": pwd}
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn("password", serializer.errors)

    def test_non_unique_fields(self):
        non_unique_data = [
            ("existing", "unique_email@example.com", "username"),
            ("uniqueuser", "existing@example.com", "email"),
        ]
        for username, email, field in non_unique_data:
            with self.subTest(field=field):
                data = {"username": username, "email": email, "password": "StrongPass123", "password2": "StrongPass123"}
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn(field, serializer.errors)


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
            data={"uid": self.uid, "token": self.token, "password": "NewStrongPass123"}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewStrongPass123"))

    def test_invalid_uid_or_token(self):
        test_cases = [
            ({"uid": "invalid", "token": self.token, "password": "NewPass123"}, "non_field_errors"),
            ({"uid": self.uid, "token": "invalid", "password": "NewPass123"}, "non_field_errors"),
        ]
        for data, error_field in test_cases:
            with self.subTest(data=data):
                serializer = PasswordResetConfirmSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn(error_field, serializer.errors)

    def test_short_password(self):
        serializer = PasswordResetConfirmSerializer(
            data={"uid": self.uid, "token": self.token, "password": "123"}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)