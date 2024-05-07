import uuid
from django.db import models
from django.contrib.auth.models import User

from chat.models import Chat
from kdc.crypto_utils import Caesar

def generate_unique_session_key():
    while True:
        key = uuid.uuid4().hex
        if not SessionKey.objects.filter(session_key=key).exists():
            break
    return key

class SessionKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="session_keys")
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="session_keys")
    session_key = models.CharField(max_length=255, default=generate_unique_session_key)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Session Key for {self.user} and {self.chat} ({self.session_key})"
    
class CaesarConnection(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="caesar_connections")
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="caesar_connections")
    caesar_key = models.IntegerField(default=Caesar.generate_key)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Caesar Connection for {self.user} in {self.chat} ({self.caesar_key})"