from django.urls import path
from . import views

urlpatterns = [
    path("request/", views.request_session_key, name="request_session_key"),
    path("reset/", views.delete_all_session_keys, name="delete_all_session_keys"),
]
