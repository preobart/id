from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.middleware.csrf import get_token
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.csrf import ensure_csrf_cookie

from defender import utils
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


User = get_user_model()

@api_view(["GET"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def csrf_view(request):
    return Response({
        "token": get_token(request)
    }, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        login(request, user) 
        return Response(
            {"user": UserSerializer(user).data},
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get("username")
    password = request.data.get("password")
    failure_limit = getattr(settings, "DEFENDER_LOGIN_FAILURE_LIMIT", 2)
    cooloff_time = utils.get_lockout_cooloff_time(ip_address=utils.get_ip(request), username=username)
    lockout_detail = (
        f"You have attempted to login {failure_limit + 1} times with no success. "
        f"Your account is locked for {cooloff_time} seconds."
    )

    if utils.is_already_locked(request, get_username=lambda r: username):
        return Response({"detail": lockout_detail}, status=status.HTTP_403_FORBIDDEN)

    user = authenticate(request, username=username, password=password)
    
    if not utils.check_request(request, user is None, get_username=lambda r: username):
        return Response({"detail": lockout_detail}, status=status.HTTP_403_FORBIDDEN)

    if user is None:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    login(request, user)
    return Response({"user": UserSerializer(user).data}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def logout_view(request):
    logout(request)
    return Response({"detail": "Logged out"})


@api_view(["GET"])
def userinfo_view(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


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
