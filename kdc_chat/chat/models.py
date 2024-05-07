from django.db import models
from django.contrib.auth.models import User
from kdc.crypto_utils import generate_rsa_keypair

class Chat(models.Model):
    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    rsa_keypair = models.TextField(default=generate_rsa_keypair)

    def __str__(self):
        return self.name
    
class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="messages")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="messages")
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content
    
    class Meta:
        ordering = ("timestamp",)