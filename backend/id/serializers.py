from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .utils import is_email_verified


User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    token = serializers.CharField(required=True, write_only=True)
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
        fields = ("first_name", "last_name", "email", "password", "password2", "token")

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
        validated_data.pop("token")
        validated_data["username"] = validated_data["email"]
        user = User.objects.create_user(**validated_data)
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email")


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        try:
            self.user = User.objects.get(email=email)
        except User.DoesNotExist as e:
            raise serializers.ValidationError(["User with this email does not exist"]) from e
        return email


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        errors = {}
        try:
            uid = force_str(urlsafe_base64_decode(attrs["uid"]))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, User.DoesNotExist) as e:
            errors["non_field_errors"] = ["Invalid user identification"]
            raise serializers.ValidationError(errors) from e

        if not default_token_generator.check_token(user, attrs["token"]):
            errors["non_field_errors"] = ["Invalid or expired token"]
            raise serializers.ValidationError(errors)

        try:
            validate_password(attrs["password"], user)
        except DjangoValidationError as e:
            errors["password"] = e.messages
            raise serializers.ValidationError(errors) from e

        attrs["user"] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data["user"]
        user.set_password(self.validated_data["password"])
        user.save()
        return user


class EmailVerificationRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(["User with this email already exists"])
        return email


class EmailVerificationConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(required=True, min_length=6, max_length=6)

    def validate_code(self, code):
        if not code.isdigit():
            raise serializers.ValidationError(["Code must contain only digits"])
        return code
