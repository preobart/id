from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie

from defender import utils
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from waffle import flag_is_active, get_waffle_flag_model

from .errors import CaptchaValidationError, EmailSendError
from .serializers import (
    CheckEmailSerializer,
    EmailVerificationConfirmSerializer,
    LoginSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    PasswordResetVerifySerializer,
    UserRegistrationSerializer,
    UserSerializer,
)
from .utils import (
    clear_password_reset,
    clear_verification,
    generate_and_store_code,
    generate_and_store_password_reset_code,
    is_password_reset_verified,
    mark_email_verified,
    mark_password_reset_verified,
    send_verification_code,
    validate_captcha,
    verify_code,
    verify_password_reset_code,
)


User = get_user_model()
Flag = get_waffle_flag_model()

class EmailVerificationThrottle(AnonRateThrottle):
    scope = "email_verification"


class RegisterView(APIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            email = serializer.validated_data["email"]
            clear_verification(email)
            login(request, user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        failure_limit = getattr(settings, "DEFENDER_LOGIN_FAILURE_LIMIT", 2)
        cooloff_time = utils.get_lockout_cooloff_time(ip_address=utils.get_ip(request), username=email)
        lockout_detail = (
            f"You have attempted to login {failure_limit + 1} times with no success. "
            f"Your account is locked for {cooloff_time} seconds."
        )

        if utils.is_already_locked(request, get_username=lambda r: email):
            return Response({"detail": lockout_detail}, status=status.HTTP_403_FORBIDDEN)

        user = authenticate(request, username=email, password=password)

        if not utils.check_request(request, user is None, get_username=lambda r: email):
            return Response({"detail": lockout_detail}, status=status.HTTP_403_FORBIDDEN)

        if user is None:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        login(request, user)
        return Response({"user": UserSerializer(user).data}, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [EmailVerificationThrottle]
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]

        if flag_is_active(request, "email_verification_captcha"):
            token = request.data.get("token")
            remote_ip = request.META.get("REMOTE_ADDR")
            try:
                validate_captcha(token, remote_ip)
            except CaptchaValidationError:
                return Response(
                    {"token": ["Invalid or missing captcha"]},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            send_verification_code(email, generate_and_store_password_reset_code)
        except EmailSendError:
            return Response(
                {"detail": "Failed to send email. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"detail": "Password reset code has been sent to your email"},
            status=status.HTTP_200_OK,
        )


class PasswordResetVerifyView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetVerifySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        code = serializer.validated_data["code"]

        if verify_password_reset_code(email, code):
            mark_password_reset_verified(email)
            return Response(
                {"verified": True, "detail": "Password reset code verified successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"code": ["Invalid or expired verification code"]},
            status=status.HTTP_400_BAD_REQUEST,
        )


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        if not is_password_reset_verified(email):
            return Response(
                {"email": ["Email must be verified before password reset"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer.save()
        clear_password_reset(email)
        return Response(
            {"detail": "Password has been reset successfully"},
            status=status.HTTP_200_OK,
        )


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]
    serializer_class = EmailVerificationConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            code = serializer.validated_data["code"]

            if verify_code(email, code):
                mark_email_verified(email)
                return Response(
                    {"verified": True, "detail": "Email verified successfully"},
                    status=status.HTTP_200_OK,
                )
            return Response({"code": ["Invalid or expired verification code"]}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckEmailView(APIView):
    permission_classes = [AllowAny]
    serializer_class = CheckEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        user_exists = User.objects.filter(email=email).exists()

        if user_exists:
            return Response({"action": "login"}, status=status.HTTP_200_OK)

        if flag_is_active(request, "email_verification_captcha"):
            token = request.data.get("token")
            remote_ip = request.META.get("REMOTE_ADDR")
            try:
                validate_captcha(token, remote_ip)
            except CaptchaValidationError:
                return Response(
                    {"token": ["Invalid or missing captcha"]},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            send_verification_code(email, generate_and_store_code)
        except EmailSendError:
            return Response(
                {"detail": "Failed to send email. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"action": "register", "detail": "Verification code has been sent to your email"},
            status=status.HTTP_200_OK,
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def logout_view(request):
    logout(request)
    return Response({"detail": "Logged out"})


@api_view(["GET"])
@permission_classes([AllowAny])
def feature_flags_view(request):
    flags = Flag.objects.filter(target__in=["frontend", "both"])
    active_flags = [flag.name for flag in flags if flag_is_active(request, flag.name)]
    return Response({"flags": active_flags}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def csrf_view(request):
    return Response({"token": get_token(request)}, status=status.HTTP_200_OK)


@api_view(["GET"])
def userinfo_view(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)
