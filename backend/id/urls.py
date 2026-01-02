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
                path("csrf", views.csrf_view, name="csrf"),
                path("userinfo", views.userinfo_view, name="userinfo"),
                path("password-reset", views.PasswordResetView.as_view(), name="password-reset"),
                path(
                    "password-reset-verify",
                    views.PasswordResetVerifyView.as_view(),
                    name="password-reset-verify",
                ),
                path(
                    "password-reset-confirm",
                    views.PasswordResetConfirmView.as_view(),
                    name="password-reset-confirm",
                ),
                path(
                    "verify-email",
                    views.VerifyEmailView.as_view(),
                    name="verify-email",
                ),
                path(
                    "check-email",
                    views.CheckEmailView.as_view(),
                    name="check-email",
                ),
            ]
        ),
    ),
]

