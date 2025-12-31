from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.middleware.csrf import get_token
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.csrf import ensure_csrf_cookie

from defender import utils
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from waffle import flag_is_active
from waffle.models import Flag

from .serializers import (
    CheckEmailSerializer,
    EmailVerificationConfirmSerializer,
    LoginSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)
from .utils import (
    check_smartcaptcha,
    clear_verification,
    generate_and_store_code,
    mark_email_verified,
    verify_code,
)


User = get_user_model()

@api_view(["GET"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def csrf_view(request):
    return Response({
        "token": get_token(request)
    }, status=status.HTTP_200_OK)


@extend_schema(
    request=UserRegistrationSerializer,
    responses={201: UserSerializer, 400: {"description": "Validation error"}},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        email = serializer.validated_data["email"]
        clear_verification(email)
        login(request, user)
        return Response(
            {"user": UserSerializer(user).data},
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=LoginSerializer,
    responses={200: UserSerializer, 401: {"description": "Invalid credentials"}, 403: {"description": "Account locked"}},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
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


@api_view(["POST"])
def logout_view(request):
    logout(request)
    return Response({"detail": "Logged out"})


@api_view(["GET"])
def userinfo_view(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@extend_schema(
    request=PasswordResetSerializer,
    responses={200: {"description": "Password reset email sent"}, 400: {"description": "Validation error"}},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_view(request):
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = (
            f"{request.build_absolute_uri('/auth/password-reset-confirm/')}?uid={uid}&token={token}"
        )

        send_mail(
            subject="Password Reset",
            message=f"Click the link to reset your password: {reset_link}",
            from_email=None,
            recipient_list=[user.email],
        )

        return Response(
            {"detail": ("Password reset email has been sent.")}, status=status.HTTP_200_OK
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=PasswordResetConfirmSerializer,
    responses={200: {"description": "Password reset successfully"}, 400: {"description": "Validation error"}},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_confirm_view(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {"detail": ("Password has been reset successfully")}, status=status.HTTP_200_OK
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationThrottle(AnonRateThrottle):
    scope = "email_verification"


@extend_schema(
    request=EmailVerificationConfirmSerializer,
    responses={200: {"description": "Email verified successfully"}},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_email_view(request):
    serializer = EmailVerificationConfirmSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data["email"]
        code = serializer.validated_data["code"]

        if verify_code(email, code):
            mark_email_verified(email)
            return Response(
                {"verified": True, "detail": "Email verified successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"code": ["Invalid or expired verification code"]},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    request=CheckEmailSerializer,
    responses={
        200: {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["login", "register"]},
                "detail": {"type": "string"},
            },
        },
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([EmailVerificationThrottle])
def check_email_view(request):
    serializer = CheckEmailSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data["email"]
    user_exists = User.objects.filter(email=email).exists()
    
    if user_exists:
        return Response(
            {"action": "login"},
            status=status.HTTP_200_OK,
        )
    
    if flag_is_active(request, "email_verification_captcha"):
        token = request.data.get("token")
        remote_ip = request.META.get("REMOTE_ADDR")

        if not check_smartcaptcha(token, remote_ip):
            return Response(
                {"token": ["Invalid or missing captcha"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
    
    code = generate_and_store_code(email)
    try:
        send_mail(
            subject="Email Verification Code",
            message=f"Your verification code is: {code}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
    except Exception:
        return Response(
            {"detail": "Failed to send verification email. Please try again later."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    
    return Response(
        {"action": "register", "detail": "Verification code has been sent to your email"},
        status=status.HTTP_200_OK,
    )


@extend_schema(
    responses={200: {"type": "object", "properties": {"flags": {"type": "array", "items": {"type": "string"}}}}},
)
@api_view(["GET"])
@permission_classes([AllowAny])
def feature_flags_view(request):
    active_flags = []
    flags = Flag.objects.filter(
        category__target__in=["frontend", "both"]
    ).select_related("category")
    
    for flag in flags:
        if flag_is_active(request, flag.name):
            active_flags.append(flag.name)
    
    return Response({"flags": active_flags}, status=status.HTTP_200_OK)
