import json

from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async

from kdc.models import CaesarConnection
from kdc.crypto_utils import Caesar

from .models import Message, Chat
from django.contrib.auth.models import User

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
        caesar_key = CaesarConnection.objects.get(user=User.objects.get(username=username), chat=Chat.objects.get(slug=chat_name)).caesar_key
        decrypted_message = Caesar.decrypt(message, caesar_key)
        return decrypted_message

    @sync_to_async
    def save_message(self, message, username, chat_name):
        user = User.objects.get(username=username)
        chat = Chat.objects.get(slug=chat_name)
        Message.objects.create(user=user, chat=chat, content=message)