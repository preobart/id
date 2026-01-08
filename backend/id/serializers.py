from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .managers import VerificationManager
from .utils.ip_utils import get_client_ip


User = get_user_model()


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    email = serializers.EmailField(validators=[UniqueValidator(queryset=User.objects.all())])

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "password", "password2")

    def validate(self, data):
        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password": "Passwords do not match"})

        try:
            validate_password(data["password"])
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": e.messages}) from e

        request = self.context.get("request")
        ip_address = get_client_ip(request)
        
        if not VerificationManager(data["email"], ip_address, "email_verification").is_verified():
            raise serializers.ValidationError({"email": "Email verification required"})

        return data

    def create(self, validated_data):
        validated_data.pop("password2")
        validated_data["username"] = validated_data["email"]
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class CodeSendSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code_type = serializers.ChoiceField(
        choices=[("password_reset", "password_reset"), ("email_verification", "email_verification")]
    )
    token = serializers.CharField(required=False, write_only=True, allow_blank=True)


class CodeVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)
    code_type = serializers.ChoiceField(
        choices=[("password_reset", "password_reset"), ("email_verification", "email_verification")]
    )

    def validate_code(self, code):
        if len(code) != 6 or not code.isdigit():
            raise serializers.ValidationError("Code must be 6 digits")
        return code


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            user = User.objects.get(username=data["email"])
        except User.DoesNotExist as e:
            raise serializers.ValidationError({"email": "User not found"}) from e

        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password": "Passwords do not match"})

        try:
            validate_password(data["password"], user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": e.messages}) from e

        data["user"] = user
        return data

    def save(self, **kwargs):
        user = self.validated_data["user"]
        user.set_password(self.validated_data["password"])
        user.save()
        return user


class CheckEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        if not User.objects.filter(username=email).exists():
            raise serializers.ValidationError("User not found")
        return email


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email")
