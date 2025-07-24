from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.TextField()
    public_key = models.TextField()
    sign_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    
    def update_sign_count(self, new_count):
        if new_count > self.sign_count:
            self.sign_count = new_count
            self.last_used_at = timezone.now()
            self.save()
    
    def __str__(self):
        return f"{self.user.username}'s credential {self.credential_id[:16]}..."