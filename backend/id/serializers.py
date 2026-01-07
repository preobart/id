from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .managers import VerificationManager
from .response_codes import ResponseCode
from .utils.ip_utils import get_client_ip


User = get_user_model()


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(), message=[ResponseCode.EMAIL_ALREADY_EXISTS]
            )
        ],
    )

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "password", "password2")

    def validate(self, data):
        errors = {}
        if data["password"] != data["password2"]:
            errors["password"] = [ResponseCode.PASSWORD_MISMATCH]

        try:
            validate_password(data["password"])
        except DjangoValidationError:
            password_errors = errors.get("password", [])
            password_errors.append(ResponseCode.PASSWORD_WEAK)
            errors["password"] = password_errors

        request = self.context.get("request")
        ip_address = get_client_ip(request)
        if not VerificationManager(data["email"], ip_address, "email_verification").is_verified():
            errors["email"] = [ResponseCode.EMAIL_VERIFICATION_REQUIRED]

        if errors:
            raise serializers.ValidationError(errors)

        return data

    def create(self, validated_data):
        validated_data.pop("password2")
        validated_data["username"] = validated_data["email"]
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class CodeSendSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code_type = serializers.ChoiceField(
        choices=[("password_reset", "password_reset"), ("email_verification", "email_verification")],
        required=True
    )
    token = serializers.CharField(required=False, write_only=True, allow_blank=True)


class CodeVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(required=True, min_length=6, max_length=6)
    code_type = serializers.ChoiceField(
        choices=[("password_reset", "password_reset"), ("email_verification", "email_verification")],
        required=True
    )

    def validate_code(self, code):
        if not code.isdigit():
            raise serializers.ValidationError([ResponseCode.VALIDATION_CODE_INVALID_FORMAT])
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
            errors["email"] = [ResponseCode.USER_NOT_FOUND]
            raise serializers.ValidationError(errors) from e

        if data["password"] != data["password2"]:
            errors["password"] = [ResponseCode.PASSWORD_MISMATCH]

        try:
            validate_password(data["password"], user)
        except DjangoValidationError:
            password_errors = errors.get("password", [])
            password_errors.append(ResponseCode.PASSWORD_WEAK)
            errors["password"] = password_errors

        if errors:
            raise serializers.ValidationError(errors)

        data["user"] = user
        return data

    def save(self, **kwargs):
        user = self.validated_data["user"]
        user.set_password(self.validated_data["password"])
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email")
