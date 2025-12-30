from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from waffle.admin import FlagAdmin
from waffle.models import Flag

from .models import FlagCategory


User = get_user_model()

admin.site.unregister(User)
admin.site.unregister(Flag)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("email", "first_name", "last_name", "is_staff", "is_active", "date_joined")
    list_filter = ("is_staff", "is_superuser", "is_active")
    search_fields = ("email", "first_name", "last_name")
    ordering = ("-date_joined",)

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Personal info", {"fields": ("first_name", "last_name", "email")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "first_name", "last_name", "password1", "password2"),
            },
        ),
    )


class FlagCategoryInline(admin.StackedInline):
    model = FlagCategory
    can_delete = False
    verbose_name_plural = "Category"
    fields = ("target", "description")
    extra = 0
    max_num = 1
    min_num = 0


@admin.register(Flag)
class CustomFlagAdmin(FlagAdmin):
    inlines = [FlagCategoryInline]
    list_display = ("name", "everyone", "percent", "superusers", "staff", "authenticated", "rollout", "note", "get_category_target")
    list_filter = ("everyone", "superusers", "staff", "authenticated", "rollout")
    search_fields = ("name", "note")
    
    def get_queryset(self, request):
        """Optimize queryset with select_related"""
        try:
            return super().get_queryset(request).select_related("category")
        except Exception:
            # Fallback if category relation doesn't exist yet
            return super().get_queryset(request)
    
    def get_category_target(self, obj):
        """Display category target in list view"""
        try:
            if obj and hasattr(obj, "category"):
                category = getattr(obj, "category", None)
                if category:
                    return category.get_target_display()
        except Exception:
            pass
        return "-"
    get_category_target.short_description = "Target"


@admin.register(FlagCategory)
class FlagCategoryAdmin(admin.ModelAdmin):
    """Admin for FlagCategory model"""
    list_display = ("flag", "target", "description_preview")
    list_filter = ("target",)
    search_fields = ("flag__name", "description")
    readonly_fields = ("flag",)
    
    def description_preview(self, obj):
        """Show first 50 characters of description"""
        if obj.description:
            return obj.description[:50] + "..." if len(obj.description) > 50 else obj.description
        return "-"
    description_preview.short_description = "Description"

