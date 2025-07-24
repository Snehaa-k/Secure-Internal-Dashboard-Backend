from django.db import models
from django.contrib.auth.models import User

class Call(models.Model):
    DIRECTION_CHOICES = [
        ('incoming', 'Incoming'),
        ('outgoing', 'Outgoing'),
    ]
    
    STATUS_CHOICES = [
        ('queued', 'Queued'),
        ('ringing', 'Ringing'),
        ('in-progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('busy', 'Busy'),
        ('no-answer', 'No Answer'),
        ('canceled', 'Canceled'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='calls')
    phone_number = models.CharField(max_length=20)
    call_sid = models.CharField(max_length=100)
    direction = models.CharField(max_length=10, choices=DIRECTION_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    duration = models.IntegerField(null=True, blank=True, help_text="Duration in seconds")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.direction.title()} call to {self.phone_number} - {self.status}"