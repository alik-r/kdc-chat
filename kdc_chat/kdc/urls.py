from django.urls import path
from . import views

urlpatterns = [
    path("request/", views.request_session_key, name="request_session_key"),
    path("get/", views.get_session_key, name="get_session_key"),
    path("delete/", views.delete_session_key, name="delete_session_key"),
    path("validate/", views.get_caesar_key, name="get_caesar_key")
]
