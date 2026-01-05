from django.contrib.auth import authenticate, get_user_model, login, logout
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from waffle import flag_is_active, get_waffle_flag_model

from .errors import EmailSendError, EmailSendLimitExceededError
from .managers import EmailVerificationManager, LoginLockoutManager
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
from .utils.captcha_utils import check_smartcaptcha
from .utils.ip_utils import get_client_ip


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
            ip_address = get_client_ip(request)
            EmailVerificationManager(email, ip_address).clear()
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
        ip_address = get_client_ip(request)

        lockout_manager = LoginLockoutManager(email, ip_address)
        if lockout_manager.is_locked():
            lockout_time = lockout_manager.get_lockout_time()
            return Response({"detail": "login lockout", "time": lockout_time}, status=status.HTTP_403_FORBIDDEN)

        user = authenticate(request, username=email, password=password)

        if user is None:
            is_locked = lockout_manager.record_failed()
            if is_locked:
                lockout_time = lockout_manager.get_lockout_time()
                return Response({"detail": "login lockout", "time": lockout_time}, status=status.HTTP_403_FORBIDDEN)
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        lockout_manager.clear()
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
        ip_address = get_client_ip(request)

        if flag_is_active(request, "email_verification_captcha"):
            token = request.data.get("token")
            remote_ip = get_client_ip(request)
            if not check_smartcaptcha(token, remote_ip):
                return Response(
                    {"token": ["Invalid or missing captcha"]},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            EmailVerificationManager(f"password_reset:{email}", ip_address).send_code()
        except EmailSendLimitExceededError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
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
        ip_address = get_client_ip(request)

        verification = EmailVerificationManager(f"password_reset:{email}", ip_address)
        if verification.verify_code(code):
            verification.mark_verified()
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
        ip_address = get_client_ip(request)
        verification = EmailVerificationManager(f"password_reset:{email}", ip_address)
        if not verification.is_verified():
            return Response(
                {"email": ["Email must be verified before password reset"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer.save()
        verification.clear()
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
            ip_address = get_client_ip(request)

            verification = EmailVerificationManager(email, ip_address)
            if verification.verify_code(code):
                verification.mark_verified()
                return Response(
                    {"verified": True, "detail": "Email verified successfully"},
                    status=status.HTTP_200_OK,
                )
            return Response({"code": ["Invalid or expired verification code"]}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckEmailView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [EmailVerificationThrottle]
    serializer_class = CheckEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        ip_address = get_client_ip(request)
        user_exists = User.objects.filter(email=email).exists()

        if user_exists:
            return Response({"action": "login"}, status=status.HTTP_200_OK)

        if flag_is_active(request, "email_verification_captcha"):
            token = request.data.get("token")
            remote_ip = request.META.get("REMOTE_ADDR")
            if not check_smartcaptcha(token, remote_ip):
                return Response({"token": "Invalid or missing captcha"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            EmailVerificationManager(email, ip_address).send_code()
        except EmailSendLimitExceededError:
            return Response(
                {"detail": "Maximum number of code send attempts exceeded. Please try again in 1 hour."}, 
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
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
