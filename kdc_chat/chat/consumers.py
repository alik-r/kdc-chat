import json

from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async

from kdc.models import SessionKey
from kdc.crypto_utils import Caesar

from .models import Message, Chat
from django.contrib.auth.models import User
from django.core.cache import cache

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.chat_name = self.scope["url_route"]["kwargs"]["chat_name"]
        self.chat_group_name = f"chat_{self.chat_name}"

        await self.channel_layer.group_add(
            self.chat_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(
            self.chat_group_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data["message"]
        username = data["username"]
        chat_name = data["chat_name"]

        message = await self.decrypt_message(message, username, chat_name)

        await self.save_message(message, username, chat_name)

        await self.channel_layer.group_send(
            self.chat_group_name,
            {
                "type": "chat_message",
                "message": message,
                "username": username,
                "chat_name": chat_name
            }
        )
    
    async def chat_message(self, event):
        message = event["message"]
        username = event["username"]
        chat_name = event["chat_name"]

        await self.send(text_data=json.dumps({
            "message": message,
            "username": username,
            "chat_name": chat_name
        }))

    @sync_to_async
    def decrypt_message(self, message, username, chat_name):
        cache_key = f"{username}_{chat_name}_caesar_key"
        caesar_key = cache.get_or_set(cache_key, lambda: self.retrieve_caesar_key(username, chat_name), timeout=60*60)
        decrypted_message = Caesar.decrypt(message, caesar_key)
        return decrypted_message

    def retrieve_caesar_key(self, username, chat_name):
        try:
            user = User.objects.get(username=username)
            chat = Chat.objects.get(slug=chat_name)
            session_key = SessionKey.objects.filter(user=user, chat=chat).latest("created_at")
            return session_key.key
        except (User.DoesNotExist, Chat.DoesNotExist, SessionKey.DoesNotExist):
            return None

    @sync_to_async
    def save_message(self, message, username, chat_name):
        user = User.objects.get(username=username)
        chat = Chat.objects.get(slug=chat_name)
        Message.objects.create(user=user, chat=chat, content=message)