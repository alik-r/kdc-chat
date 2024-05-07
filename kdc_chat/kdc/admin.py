from django.contrib import admin

from .models import SessionKey, CaesarConnection

admin.site.register(SessionKey)
admin.site.register(CaesarConnection)