from django.db import models

from waffle.models import AbstractUserFlag


class Flag(AbstractUserFlag):
    TARGET_CHOICES = [
        ("frontend", "Frontend"),
        ("backend", "Backend"),
        ("both", "Both"),
    ]
    target = models.CharField(
        max_length=8,
        choices=TARGET_CHOICES,
        default="both",
        help_text="Target audience for this flag",
    )

    class Meta:
        verbose_name = "Flag"
        verbose_name_plural = "Flags"
