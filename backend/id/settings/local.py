import re

from .base import *


DEBUG = True

ALLOWED_HOSTS = ["*"]

SECRET_KEY = "secret"  # noqa: S105

STATIC_URL = "/static/"
STATIC_ROOT = base_dir_join("staticfiles")


STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

AUTH_PASSWORD_VALIDATORS = []

# Celery
CELERY_BROKER_URL = env("CELERY_BROKER_URL", default="")
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CORS_ALLOWED_ORIGIN_REGEXES = [
    re.compile(r)
    for r in env("CORS_ALLOWED_ORIGIN_REGEXES", "").split(",")
    if r
]

CSRF_TRUSTED_ORIGINS = env("CSRF_TRUSTED_ORIGINS", "").split(",")
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
