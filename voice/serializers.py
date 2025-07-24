from rest_framework import serializers
from .models import Call
from contacts.models import Contact

class CallSerializer(serializers.ModelSerializer):
    contact_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Call
        fields = ['id', 'phone_number', 'call_sid', 'direction', 'status', 'duration', 'created_at', 'updated_at', 'contact_name']
        read_only_fields = ['created_at', 'updated_at']
    
    def get_contact_name(self, obj):
        try:
            contact = Contact.objects.filter(phone_number=obj.phone_number).first()
            return contact.name if contact else 'Unknown'
        except:
            return 'Unknown'