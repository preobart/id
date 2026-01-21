from django.contrib import admin

from waffle import get_waffle_flag_model
from waffle.admin import FlagAdmin


Flag = get_waffle_flag_model()

admin.site.register(Flag, FlagAdmin)
