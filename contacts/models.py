from django.db import models
from django.contrib.auth.models import User

class Contact(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='contacts')
    name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(blank=True, null=True)
    tags = models.CharField(max_length=200, blank=True, help_text="Comma-separated tags")
    notes = models.TextField(blank=True)
    last_contacted = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        unique_together = ['user', 'phone_number']
    
    def __str__(self):
        return f"{self.name} - {self.phone_number}"
    
    @property
    def tag_list(self):
        """Return tags as a list"""
        return [tag.strip() for tag in self.tags.split(',') if tag.strip()]