from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from chat.models import Chat
from .crypto_utils import MiniRSA, print_with_timestamp
from .models import SessionKey
from django.contrib.auth.models import User

@csrf_exempt
def request_session_key(request):
    if request.method == "POST":
        user_id = request.POST.get("user")
        chat_slug = request.POST.get("chat_slug")
        nonce_a = request.POST.get("nonce_a")
        encrypted_nonce = request.POST.get("encrypted_nonce")

        user = get_object_or_404(User, id=user_id)
        chat = get_object_or_404(Chat, slug=chat_slug)

        print_with_timestamp(f"> (KDC) User <{user.username}> requested session key for chat <{chat.slug}>.")

        session = SessionKey.objects.create(user=user, chat=chat)

        print_with_timestamp(f"> (KDC) Session key <{session.key}> created for user <{user.username}> and chat <{chat.slug}>.")

        encrypted_nonce_a = MiniRSA.encrypt_with_keypair(nonce_a, user.profile.rsa_keypair)
        encrypted_session_key_a = MiniRSA.encrypt_with_keypair(session.key, user.profile.rsa_keypair)
        encrypted_chat_slug = MiniRSA.encrypt_with_keypair(chat_slug, user.profile.rsa_keypair)
        encrypted_session_key_b = MiniRSA.encrypt_with_keypair(session.key, chat.rsa_keypair)

        print_with_timestamp(f"> (KDC) Responding to user <{user.username}>...")

        return JsonResponse({"nonce_a": encrypted_nonce_a, "session_key_a": encrypted_session_key_a, "chat_slug": encrypted_chat_slug, "session_key_b": encrypted_session_key_b, "encrypted_nonce": encrypted_nonce})
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

def delete_all_session_keys(request):
    if request.method != "DELETE":
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
    user = get_object_or_404(User.objects.prefetch_related("session_keys"), id=request.user.id)
    user.session_keys.all().delete()
    return JsonResponse({"message": "All session keys deleted"}, status=204)