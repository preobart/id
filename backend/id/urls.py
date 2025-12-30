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
                path("register", views.register_view, name="register"),
                path("login", views.login_view, name="login"),
                path("logout", views.logout_view, name="logout"),
                path("csrf", views.csrf_view, name="csrf"),
                path("userinfo", views.userinfo_view, name="userinfo"),
                path("password-reset", views.password_reset_view, name="password-reset"),
                path(
                    "password-reset-confirm",
                    views.password_reset_confirm_view,
                    name="password-reset-confirm",
                ),
                path(
                    "verify-email/request",
                    views.email_verification_request_view,
                    name="verify-email-request",
                ),
                path(
                    "verify-email/confirm",
                    views.email_verification_confirm_view,
                    name="verify-email-confirm",
                ),
            ]
        ),
    ),
]

