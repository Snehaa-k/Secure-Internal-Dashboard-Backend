from rest_framework import viewsets, filters
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from .models import Contact
from .serializers import ContactSerializer

class ContactViewSet(viewsets.ModelViewSet):
    serializer_class = ContactSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['tags']
    search_fields = ['name', 'phone_number', 'email', 'tags']
    ordering_fields = ['name', 'created_at', 'last_contacted']
    ordering = ['name']
    
    def get_queryset(self):
        return Contact.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)