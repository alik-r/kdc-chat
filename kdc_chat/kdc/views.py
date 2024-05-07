from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from chat.models import Chat
from .crypto_utils import Caesar, MiniRSA
from .models import CaesarConnection, SessionKey
from django.contrib.auth.models import User

@csrf_exempt
def request_session_key(request):
    if request.method == "POST":
        user_id = request.POST.get("user")
        chat_slug = request.POST.get("chat_slug")
        
        user = get_object_or_404(User, id=user_id)
        chat = get_object_or_404(Chat, slug=chat_slug)
        
        session = SessionKey.objects.create(user=user, chat=chat)
        
        return JsonResponse({"session_key": session.session_key})
    else:
        return JsonResponse({"error": "Invalid request method"})

def get_session_key(request):
    if request.method == "GET":
        user_id = request.user.id
        chat_slug = request.GET.get("chat_slug")
        
        user = get_object_or_404(User, id=user_id)
        chat = get_object_or_404(Chat, slug=chat_slug)
        
        session = SessionKey.objects.create(user=user, chat=chat)
        if session:
            return JsonResponse({"session_key": session.session_key})
        else:
            return JsonResponse({"error": "Session key not found"})
    else:
        return JsonResponse({"error": "Invalid request method"})
    
def delete_session_key(request):
    if request.method != "DELETE":
        return JsonResponse({"error": "Invalid request method"})

    user_id = request.user.id
    chat_slug = request.GET.get("chat_slug")
        
    user = get_object_or_404(User, id=user_id)
    chat = get_object_or_404(Chat, slug=chat_slug)

    session = SessionKey.objects.create(user=user, chat=chat).first()
    if session:
        session.delete()
        return JsonResponse({"message": "Session key deleted"})
    else:
        return JsonResponse({"error": "Session key not found"})
    
@csrf_exempt
def get_caesar_key(request):
    if request.method != "POST":
        return JsonResponse({"message": "Invalid request method"})
    
    slug = request.POST.get("chat_slug")
    user_id = request.POST.get("user")
    encrypted_session_key = request.POST.get("session_key")

    chat = Chat.objects.get(slug=slug)
    user = User.objects.get(id=user_id)

    rsa = MiniRSA()
    rsa.load_keypair_from_str(chat.rsa_keypair)
    session_key = rsa.decrypt(encrypted_session_key)

    if chat.session_keys.filter(user=user, session_key=session_key).exists():
        caesar_conn = CaesarConnection.objects.create(user=user, chat=chat)
        caesar_key = str(caesar_conn.caesar_key)

        rsa.load_keypair_from_str(user.profile.rsa_keypair)
        caesar_key_encrypted = rsa.encrypt(caesar_key)

        # Delete the session key
        SessionKey.objects.filter(user=user, chat=chat, session_key=session_key).delete()

        return JsonResponse({"caesar_key": caesar_key_encrypted})
    else:
        return JsonResponse({"message": "Invalid session key"})
