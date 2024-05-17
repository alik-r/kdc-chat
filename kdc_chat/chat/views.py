import requests
from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.core.cache import cache

from kdc.crypto_utils import MiniRSA, generate_nonce, Caesar, generate_timestamp, print_with_timestamp

from .models import Chat

@login_required
def chats(request):
    chats = Chat.objects.all()
    return render(request, "chat/chats.html", {"chats": chats})

@login_required
@csrf_exempt
def chat(request, slug):
    chat = Chat.objects.get(slug=slug)

    print(f"\n\n##### User <{request.user.username}> requested to join chat <{chat.slug}> #####")

    # B -> A: E(Kb, Nb' || A)
    nonce_b_prime_generated = generate_nonce()
    b_message = nonce_b_prime_generated + f",{request.user.id}"
    encrypted_nonce_b_prime = MiniRSA.encrypt_with_keypair(b_message, chat.rsa_keypair)

    print_with_timestamp(f"> Chat <{chat.slug}> responded with encrypted nonce and user id: <{encrypted_nonce_b_prime}>")

    # A -> S: A, B, Na, E(Kb, Nb' || A)
    # S -> A: E(Ka, Na || Kab || B || E(Kb, Kab || Nb' || A))
    nonce_a = generate_nonce()

    print_with_timestamp(f"> User <{request.user.username}> sending request to KDC with: nonce <{nonce_a}> and encrypted nonce <{encrypted_nonce_b_prime}>")

    kdc_response = requests.post(f"{settings.BASE_URL}/kdc/request/", data={"user": request.user.id, "chat_slug": chat.slug, "nonce_a": nonce_a, "encrypted_nonce": encrypted_nonce_b_prime}).json()

    print_with_timestamp(f"> KDC responded with: {str(dict(kdc_response))}")

    decrypted_nonce_a = MiniRSA.decrypt_with_keypair(kdc_response["nonce_a"], request.user.profile.rsa_keypair)
    print_with_timestamp(f"> User <{request.user.username}> checking if decrypted nonce A <{decrypted_nonce_a}> equals original nonce A <{nonce_a}>: <{decrypted_nonce_a == nonce_a}>")
    if decrypted_nonce_a != nonce_a:
        return JsonResponse({
            "error": "Invalid nonce", "decrypted_nonce_a": decrypted_nonce_a, "nonce_a": nonce_a
        })
    

    print_with_timestamp(f"> User <{request.user.username}> decrypted the session key and chat slug.")
    session_key_a = MiniRSA.decrypt_with_keypair(kdc_response["session_key_a"], request.user.profile.rsa_keypair)

    decrypted_chat_slug = MiniRSA.decrypt_with_keypair(kdc_response["chat_slug"], request.user.profile.rsa_keypair)

    print_with_timestamp(f"> User <{request.user.username}> checking if decrypted chat slug <{decrypted_chat_slug}> is correct: <{decrypted_chat_slug == chat.slug}>")

    if decrypted_chat_slug != chat.slug:
        return JsonResponse({"error": "Invalid chat slug"})

    print_with_timestamp(f"> User <{request.user.username}> forwarding encrypted message to chat <{chat.slug}> to share the session key...")
    # A -> B: E(Kb, Kab || Nb' || A)
    session_key_b = MiniRSA.decrypt_with_keypair(kdc_response["session_key_b"], chat.rsa_keypair)

    print_with_timestamp(f"> Chat <{chat.slug}> decrypting the nonce and checking its correctness...")
    decrypted_nonce_b_prime = MiniRSA.decrypt_with_keypair(kdc_response["encrypted_nonce"], chat.rsa_keypair)
    nonce_b_prime, a_id = decrypted_nonce_b_prime.split(",")
    if a_id != str(request.user.id):
        return JsonResponse({"error": "Invalid user"})
    if nonce_b_prime != nonce_b_prime_generated:
        return JsonResponse({"error": "Invalid nonce 2"})
    
    # B -> A: E(Kab, Nb)
    nonce_b = generate_timestamp()
    encrypted_nonce_b = Caesar.encrypt(nonce_b, session_key_b)

    print_with_timestamp(f"> Chat <{chat.slug}> sending user <{request.user.username}> a new nonce <{nonce_b}> encrypted with the session key <{session_key_b}>")

    # A -> B: E(Kab, Nb - 1)
    decrypted_nonce_b = int(Caesar.decrypt(encrypted_nonce_b, session_key_a))
    decrypted_nonce_b -= 1
    encrypted_nonce_b_minus_one = Caesar.encrypt(decrypted_nonce_b, session_key_a)

    print_with_timestamp(f"> User <{request.user.username}> decrypts the nonce <{encrypted_nonce_b}>, performs operation, re-encrypts it, and sends it back to the chat...")

    # Bob decrypts the nonce and checks if it is correct.
    decrypted_nonce_b_minus_one = Caesar.decrypt(encrypted_nonce_b_minus_one, session_key_b)
    print_with_timestamp(f"> Chat <{chat.slug}> decrypts the nonce <{encrypted_nonce_b_minus_one}> and checks if it is correct...")
    if int(decrypted_nonce_b_minus_one) != nonce_b - 1:
        return JsonResponse({"error": "Invalid nonce 3"})

    print_with_timestamp(f"> Chat <{chat.slug}> successfully decrypted the nonce and verified it.")

    print_with_timestamp(f"> Chat between <{chat.slug}> and user <{request.user.username}> is now established. Deleting old session keys from cache...")
    cache.delete(f"{request.user.username}_{chat.slug}_caesar_key")
    messages = chat.messages.all()
    print_with_timestamp(f"> Chat <{chat.slug}> has {len(messages)} messages. Rendering chat...")
    return render(request, "chat/chat.html", {"chat": chat, "messages": messages, "caesar_key": session_key_a})