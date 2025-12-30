from django.db import models

from waffle.models import Flag


class FlagCategory(models.Model):
    FLAG_TARGETS = [
        ("frontend", "Frontend"),
        ("backend", "Backend"),
        ("both", "Both"),
    ]

    flag = models.OneToOneField(
        Flag,
        on_delete=models.CASCADE,
        related_name="category",
        help_text="The flag this category belongs to",
    )
    target = models.CharField(
        max_length=10,
        choices=FLAG_TARGETS,
        default="both",
        help_text="Target audience for this flag (frontend, backend, or both)",
    )
    description = models.TextField(
        blank=True,
        help_text="Description of what this flag controls",
    )

    class Meta:
        verbose_name = "Flag Category"
        verbose_name_plural = "Flag Categories"

    def __str__(self):
        return f"{self.flag.name} - {self.get_target_display()}"

