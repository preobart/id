from django.contrib import admin

from defender.models import AccessAttempt
from waffle import get_waffle_flag_model
from waffle.admin import FlagAdmin


Flag = get_waffle_flag_model()

admin.site.register(Flag, FlagAdmin)
admin.site.unregister(AccessAttempt)
