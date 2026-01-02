from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .utils import is_email_verified


User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(), message=["User with this email already exists"]
            )
        ],
    )

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "password", "password2")

    def validate(self, data):
        errors = {}
        if data["password"] != data["password2"]:
            errors["password"] = ["Passwords do not match"]

        try:
            validate_password(data["password"])
        except DjangoValidationError as e:
            errors["password"] = errors.get("password", []) + e.messages

        if not is_email_verified(data["email"]):
            errors["email"] = ["Email must be verified before registration"]

        if errors:
            raise serializers.ValidationError(errors)

        return data

    def create(self, validated_data):
        validated_data.pop("password2")
        validated_data["username"] = validated_data["email"]
        user = User.objects.create_user(**validated_data)
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email")


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(required=False, write_only=True, allow_blank=True)

    def validate_email(self, email):
        try:
            self.user = User.objects.get(email=email)
        except User.DoesNotExist as e:
            raise serializers.ValidationError(["User with this email does not exist"]) from e
        return email


class PasswordResetVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(required=True, min_length=6, max_length=6)

    def validate_code(self, code):
        if not code.isdigit():
            raise serializers.ValidationError(["Code must contain only digits"])
        return code


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        errors = {}
        try:
            user = User.objects.get(email=data["email"])
        except User.DoesNotExist as e:
            errors["email"] = ["User with this email does not exist"]
            raise serializers.ValidationError(errors) from e

        if data["password"] != data["password2"]:
            errors["password"] = ["Passwords do not match"]

        try:
            validate_password(data["password"], user)
        except DjangoValidationError as e:
            errors["password"] = errors.get("password", []) + e.messages

        if errors:
            raise serializers.ValidationError(errors)

        data["user"] = user
        return data

    def save(self, **kwargs):
        user = self.validated_data["user"]
        user.set_password(self.validated_data["password"])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class EmailVerificationConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(required=True, min_length=6, max_length=6)

    def validate_code(self, code):
        if not code.isdigit():
            raise serializers.ValidationError(["Code must contain only digits"])
        return code


class CheckEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    token = serializers.CharField(required=False, write_only=True, allow_blank=True)
