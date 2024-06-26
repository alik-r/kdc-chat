from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
    path("chats/", include("chat.urls")),
    path("kdc/", include("kdc.urls")),
]
