from django.contrib.auth import authenticate, get_user_model, login, logout
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from waffle import flag_is_active, get_waffle_flag_model

from .errors import EmailSendError, EmailSendLimitExceededError
from .managers import LoginLockoutManager, VerificationManager
from .response_codes import ResponseCode
from .serializers import (
    CodeSendSerializer,
    CodeVerifySerializer,
    LoginSerializer,
    PasswordResetConfirmSerializer,
    RegistrationSerializer,
    UserSerializer,
)
from .throttle import EmailVerificationThrottle
from .utils.captcha_utils import check_smartcaptcha
from .utils.ip_utils import get_client_ip


User = get_user_model()
Flag = get_waffle_flag_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]
    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
       
        user = serializer.save()
        email = serializer.validated_data["email"]
        ip_address = get_client_ip(request)

        VerificationManager(email, ip_address, "email_verification").clear()
        login(request, user)
        return Response(status=status.HTTP_201_CREATED)


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
            return Response({"code": ResponseCode.AUTH_LOGIN_LOCKOUT, "time": lockout_time}, status=status.HTTP_403_FORBIDDEN)

        user = authenticate(request, username=email, password=password)

        if user is None:
            if lockout_manager.record_failed():
                lockout_time = lockout_manager.get_lockout_time()
                return Response({"code": ResponseCode.AUTH_LOGIN_LOCKOUT, "time": lockout_time}, status=status.HTTP_403_FORBIDDEN)
            return Response({"code": ResponseCode.AUTH_INVALID_CREDENTIALS}, status=status.HTTP_401_UNAUTHORIZED)

        lockout_manager.clear()
        login(request, user)
        return Response(status=status.HTTP_200_OK)


class SendCodeView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [EmailVerificationThrottle]
    serializer_class = CodeSendSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        code_type = serializer.validated_data["code_type"]
        
        ip_address = get_client_ip(request)

        if flag_is_active(request, "smartcaptcha_enabled"):
            token = request.data.get("token")
            if not check_smartcaptcha(token, ip_address):
                return Response({"token": ResponseCode.CAPTCHA_INVALID}, status=status.HTTP_400_BAD_REQUEST)
        
        verification = VerificationManager(email, ip_address, code_type)

        try:
            verification.send_code()
        except EmailSendLimitExceededError:
            return Response({"code": ResponseCode.EMAIL_SEND_LIMIT_EXCEEDED}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except EmailSendError:
            return Response({"code": ResponseCode.EMAIL_SEND_FAILED}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(status=status.HTTP_200_OK)


class VerifyCodeView(APIView):
    permission_classes = [AllowAny]
    serializer_class = CodeVerifySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        code = serializer.validated_data["code"]
        code_type = serializer.validated_data["code_type"]

        ip_address = get_client_ip(request)
        verification = VerificationManager(email, ip_address, code_type)

        if not verification.verify_code(code):
            return Response({"code": ResponseCode.EMAIL_CODE_INVALID}, status=status.HTTP_400_BAD_REQUEST)
        
        verification.mark_verified()
        return Response(status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        ip_address = get_client_ip(request)
        verification = VerificationManager(email, ip_address, "password_reset")
        
        if not verification.is_verified():
            return Response({"email": ResponseCode.EMAIL_VERIFICATION_REQUIRED}, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        verification.clear()
        return Response(status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def logout_view(request):
    logout(request)
    return Response(status=status.HTTP_200_OK)


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


@api_view(["GET"])
@permission_classes([AllowAny])
def check_email_view(request):
    email = request.query_params.get("email")
    if not email:
        return Response({"email": ResponseCode.VALIDATION_REQUIRED}, status=status.HTTP_400_BAD_REQUEST)

    exists = User.objects.filter(email=email).exists()
    return Response({"action": "login" if exists else "register"}, status=status.HTTP_200_OK)
