import requests
from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from kdc.crypto_utils import MiniRSA

from .models import Chat

@login_required
def chats(request):
    chats = Chat.objects.all()
    return render(request, "chat/chats.html", {"chats": chats})

@login_required
@csrf_exempt
def chat(request, slug):
    chat = Chat.objects.get(slug=slug)
    messages = chat.messages.all()

    caesar_key = None
    if not chat.caesar_connections.filter(user=request.user).exists():
        session_key = requests.post(f"{settings.BASE_URL}/kdc/request/", data={"user": request.user.id, "chat_slug": chat.slug}).json()["session_key"]

        encrypted_session_key = MiniRSA.encrypt_with_key(session_key, MiniRSA.get_public_key_from_keypair_str(chat.rsa_keypair))

        response = requests.post(f"{settings.BASE_URL}/kdc/validate/", data={"user": request.user.id, "chat_slug": chat.slug, "session_key": encrypted_session_key})
        encrypted_caesar_key = response.json()["caesar_key"]

        rsa = MiniRSA()
        rsa.load_keypair_from_str(request.user.profile.rsa_keypair)
        caesar_key = rsa.decrypt(encrypted_caesar_key)
    else:
        caesar_key = chat.caesar_connections.get(user=request.user).caesar_key
    return render(request, "chat/chat.html", {"chat": chat, "messages": messages, "caesar_key": caesar_key})