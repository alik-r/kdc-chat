import requests
from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.core.cache import cache

from kdc.crypto_utils import MiniRSA, generate_nonce, Caesar, generate_timestamp

from .models import Chat

@login_required
def chats(request):
    chats = Chat.objects.all()
    return render(request, "chat/chats.html", {"chats": chats})

@login_required
@csrf_exempt
def chat(request, slug):
    chat = Chat.objects.get(slug=slug)

    # B -> A: E(Kb, Nb' || A)
    nonce_b_prime_generated = generate_nonce()
    b_message = nonce_b_prime_generated + f",{request.user.id}"
    encrypted_nonce_b_prime = MiniRSA.encrypt_with_keypair(b_message, chat.rsa_keypair)

    # A -> S: A, B, Na, E(Kb, Nb' || A)
    # S -> A: E(Ka, Na || Kab || B || E(Kb, Kab || Nb' || A))
    nonce_a = generate_nonce()
    kdc_response = requests.post(f"{settings.BASE_URL}/kdc/request/", data={"user": request.user.id, "chat_slug": chat.slug, "nonce_a": nonce_a, "encrypted_nonce": encrypted_nonce_b_prime}).json()

    decrypted_nonce_a = MiniRSA.decrypt_with_keypair(kdc_response["nonce_a"], request.user.profile.rsa_keypair)
    if decrypted_nonce_a != nonce_a:
        return JsonResponse({
            "error": "Invalid nonce", "decrypted_nonce_a": decrypted_nonce_a, "nonce_a": nonce_a
        })
    
    session_key_a = MiniRSA.decrypt_with_keypair(kdc_response["session_key_a"], request.user.profile.rsa_keypair)

    decrypted_chat_slug = MiniRSA.decrypt_with_keypair(kdc_response["chat_slug"], request.user.profile.rsa_keypair)
    if decrypted_chat_slug != chat.slug:
        return JsonResponse({"error": "Invalid chat slug"})

    # A -> B: E(Kb, Kab || Nb' || A)
    session_key_b = MiniRSA.decrypt_with_keypair(kdc_response["session_key_b"], chat.rsa_keypair)

    decrypted_nonce_b_prime = MiniRSA.decrypt_with_keypair(kdc_response["encrypted_nonce"], chat.rsa_keypair)
    nonce_b_prime, a_id = decrypted_nonce_b_prime.split(",")
    if a_id != str(request.user.id):
        return JsonResponse({"error": "Invalid user"})
    if nonce_b_prime != nonce_b_prime_generated:
        return JsonResponse({"error": "Invalid nonce 2"})
    
    # B -> A: E(Kab, Nb)
    nonce_b = generate_timestamp()
    encrypted_nonce_b = Caesar.encrypt(nonce_b, session_key_b)

    # A -> B: E(Kab, Nb - 1)
    decrypted_nonce_b = int(Caesar.decrypt(encrypted_nonce_b, session_key_a))
    decrypted_nonce_b -= 1
    encrypted_nonce_b_minus_one = Caesar.encrypt(decrypted_nonce_b, session_key_a)

    # Bob decrypts the nonce and checks if it is correct.
    decrypted_nonce_b_minus_one = Caesar.decrypt(encrypted_nonce_b_minus_one, session_key_b)
    if int(decrypted_nonce_b_minus_one) != nonce_b - 1:
        return JsonResponse({"error": "Invalid nonce 3"})

    cache.delete(f"{request.user.username}_{chat.slug}_caesar_key")
    messages = chat.messages.all()
    return render(request, "chat/chat.html", {"chat": chat, "messages": messages, "caesar_key": session_key_a})