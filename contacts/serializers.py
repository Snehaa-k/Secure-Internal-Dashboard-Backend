from rest_framework import serializers
from .models import Contact

class ContactSerializer(serializers.ModelSerializer):
    tag_list = serializers.ReadOnlyField()
    
    class Meta:
        model = Contact
        fields = ['id', 'name', 'phone_number', 'email', 'tags', 'tag_list', 'notes', 'last_contacted', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']