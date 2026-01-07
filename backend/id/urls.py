from django.contrib import admin
from django.urls import include, path

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework.permissions import IsAdminUser

from . import views


urlpatterns = [
    path("admin", admin.site.urls, name="admin"),
    path(
        "schema",
        SpectacularAPIView.as_view(permission_classes=[IsAdminUser]),
        name="schema",
    ),
    path(
        "docs",
        SpectacularSwaggerView.as_view(url_name="schema", permission_classes=[IsAdminUser]),
        name="swagger-ui",
    ),
    path("feature-flags", views.feature_flags_view, name="feature-flags"),
    path(
        "auth/",
        include(
            [
                path("register", views.RegisterView.as_view(), name="register"),
                path("login", views.LoginView.as_view(), name="login"),
                path("logout", views.logout_view, name="logout"),
                path("userinfo", views.userinfo_view, name="userinfo"),
                path("csrf", views.csrf_view, name="csrf"),
                path("check-email", views.check_email_view, name="check-email"),
                path("send-code", views.SendCodeView.as_view(), name="send-code"),
                path("verify-code", views.VerifyCodeView.as_view(), name="verify-code"),
                path(
                    "password-reset-confirm",
                    views.PasswordResetConfirmView.as_view(),
                    name="password-reset-confirm",
                ),
            ]
        ),
    ),
]

