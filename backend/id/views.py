import logging

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.csrf import ensure_csrf_cookie

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .serializers import (
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)


logger = logging.getLogger(__name__)



User = get_user_model()


@api_view(["POST"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def register_view(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        logger.info("New user registered: %s", user.username)
        return Response(
            {"user": UserSerializer(user).data},
            status=status.HTTP_201_CREATED,
        )
    logger.warning("Failed registration attempt: %s", serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login_view(request):
    username = request.data.get("username")
    password = request.data.get("password")
    user = authenticate(request, username=username, password=password)
    if user is None:
        logger.warning("Failed login attempt for username: %s", username)
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    login(request, user)
    logger.info("User logged in: %s", username)
    return Response(
        {"user": UserSerializer(user).data},
        status=status.HTTP_200_OK,
    )

@api_view(["POST"])
def logout_view(request):
    logger.info("User logged out: %s", request.user.username if request.user.is_authenticated else "anonymous")
    logout(request)
    return Response({"message": "Logged out"})

@api_view(["GET"])
def userinfo_view(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(["POST"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def password_reset_view(request):
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.user
        logger.info("Password reset requested for user: %s", user.username)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"{request.build_absolute_uri('/password-reset-confirm/')}{uid}/{token}/"

        send_mail(
            subject="Password Reset",
            message=f"Click the link to reset your password: {reset_link}",
            from_email=None,  # Use default
            recipient_list=[user.email],
        )

        return Response({"detail": ("Password reset email has been sent.")}, status=status.HTTP_200_OK)
    logger.warning("Failed password reset attempt: %s", serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def password_reset_confirm_view(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        logger.info("Password successfully reset for user")
        return Response({"detail": ("Password has been reset successfully")}, status=status.HTTP_200_OK)
    logger.warning("Failed password reset confirm attempt: %s", serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)