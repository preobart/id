from django.contrib import admin
from django.urls import include, path

from . import views


urlpatterns = [
    path("admin/", admin.site.urls, name="admin"),
    path("auth/", include(
            [
                path("register/", views.register_view, name="register"),
                path("login/", views.login_view, name="login"),
                path("logout/", views.logout_view, name="logout"),
                path("userinfo/", views.userinfo_view, name="userinfo"),
                path("password-reset/", views.password_reset_view, name="password-reset"),
                path("password-reset-confirm/", views.password_reset_confirm_view, name="password-reset-confirm"),
                path("", include("djoser.urls.jwt")),
                path("", include("djoser.urls")), 
            ]
        )
    )
]
