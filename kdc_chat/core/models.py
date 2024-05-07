from django.db import models
from django.contrib.auth.models import User

from kdc.crypto_utils import generate_rsa_keypair

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    rsa_keypair = models.TextField(default=generate_rsa_keypair)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Profile for {self.user}"
