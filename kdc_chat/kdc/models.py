from django.db import models
from django.contrib.auth.models import User

from chat.models import Chat
from kdc.crypto_utils import Caesar, generate_timestamp

class SessionKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="session_keys")
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="session_keys")
    key = models.IntegerField(default=Caesar.generate_key)
    timestamp = models.IntegerField(default=generate_timestamp)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Session key: {self.user.username} - {self.chat.slug} - {self.key} - {self.timestamp} - {self.created_at}"