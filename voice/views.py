from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods
from twilio.twiml.voice_response import VoiceResponse
from .twilio_service import TwilioService
from .models import Call
from .serializers import CallSerializer
import logging
from twilio.twiml.voice_response import VoiceResponse

logger = logging.getLogger(__name__)

class DialCallView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        phone_number = request.data.get('phone_number')
        
        if not phone_number:
            return Response(
                {'error': 'Phone number is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if this is a Voice SDK call (no actual Twilio call needed)
        is_voice_sdk = request.data.get('voice_sdk', False)
        
        if is_voice_sdk:
            # For Voice SDK calls, just create the record
            call = Call.objects.create(
                user=request.user,
                phone_number=phone_number,
                call_sid=f"voice_sdk_{phone_number}_{request.user.id}",
                direction='outgoing',
                status='initiated'
            )
            result = {'success': True, 'call_sid': call.call_sid, 'status': 'initiated'}
        else:
            # For server-side calls, use Twilio service
            twilio_service = TwilioService()
            result = twilio_service.make_call(phone_number)
            
            if result['success']:
                # Create call record
                call = Call.objects.create(
                    user=request.user,
                    phone_number=phone_number,
                    call_sid=result['call_sid'],
                    direction='outgoing',
                    status=result['status']
                )
        
        if result['success']:
            
            # Update contact's last_contacted
            from contacts.models import Contact
            from django.utils import timezone
            try:
                contact = Contact.objects.filter(phone_number=phone_number).first()
                if contact:
                    contact.last_contacted = timezone.now()
                    contact.save()
                    logger.info(f"Updated last_contacted for contact: {contact.name}")
            except Exception as e:
                logger.error(f"Failed to update contact last_contacted: {str(e)}")
            
            return Response({
                'success': True,
                'call_id': call.id,
                'call_sid': result['call_sid'],
                'status': result['status']
            })
        else:
            return Response(
                {'error': result['error']}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class HangupCallView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, call_id):
        try:
            call = Call.objects.get(id=call_id, user=request.user)
            
            twilio_service = TwilioService()
            result = twilio_service.hangup_call(call.call_sid)
            
            if result['success']:
                call.status = 'completed'
                call.save()
                
                return Response({
                    'success': True,
                    'call_id': call_id,
                    'status': 'completed'
                })
            else:
                return Response(
                    {'error': result['error']}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
                
        except Call.DoesNotExist:
            return Response(
                {'error': 'Call not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

class CallStatusView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, call_id):
        try:
            call = Call.objects.get(id=call_id, user=request.user)
            
            twilio_service = TwilioService()
            result = twilio_service.get_call_status(call.call_sid)
            
            if result['success']:
                # Update local call record
                call.status = result['status']
                call.duration = result['duration']
                call.save()
                
                return Response({
                    'success': True,
                    'call': CallSerializer(call).data,
                    'twilio_data': result
                })
            else:
                return Response(
                    {'error': result['error']}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
                
        except Call.DoesNotExist:
            return Response(
                {'error': 'Call not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

class CallHistoryView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get local call history
        calls = Call.objects.filter(user=request.user).order_by('-created_at')
        
        # Optionally sync with Twilio
        sync_with_twilio = request.query_params.get('sync', 'false').lower() == 'true'
        
        if sync_with_twilio:
            twilio_service = TwilioService()
            twilio_result = twilio_service.get_call_history()
            
            if twilio_result['success']:
                # Update local records with Twilio data
                for twilio_call in twilio_result['calls']:
                    try:
                        local_call = Call.objects.get(call_sid=twilio_call['call_sid'])
                        local_call.status = twilio_call['status']
                        local_call.duration = twilio_call['duration']
                        local_call.save()
                    except Call.DoesNotExist:
                        pass  # Call not in local database
        
        serializer = CallSerializer(calls, many=True)
        return Response(serializer.data)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class TwilioWebhookView(APIView):
    permission_classes = []  # Twilio webhooks don't use authentication
    authentication_classes = []  # No authentication required
    
    def dispatch(self, request, *args, **kwargs):
        # Handle ngrok browser warning
        response = super().dispatch(request, *args, **kwargs)
        response['ngrok-skip-browser-warning'] = 'true'
        return response
    
    def post(self, request):
        """Handle TwiML for outgoing calls"""
        try:
            # Log all request data
            logger.info(f"TwiML POST request data: {dict(request.POST)}")
            logger.info(f"TwiML GET request params: {dict(request.GET)}")
            
            # Try to get phone number from different sources
            to_number = request.POST.get('To') or request.GET.get('To')
            from_number = request.POST.get('From') or request.GET.get('From')
            
            logger.info(f"TwiML request: From {from_number} To {to_number}")
            
            # Generate TwiML to dial the number
            response = VoiceResponse()
            
            if to_number:
                # Remove 'client:' prefix if present
                if to_number.startswith('client:'):
                    to_number = to_number.replace('client:', '')
                
                logger.info(f"Dialing: {to_number}")
                response.dial(to_number)
            else:
                logger.warning("No phone number provided in TwiML request")
                response.say("Hello from your dashboard webhook!")
            
            twiml_str = str(response)
            logger.info(f"Generated TwiML: {twiml_str}")
            
            return HttpResponse(twiml_str, content_type='application/xml')
            
        except Exception as e:
            logger.error(f"Error in TwiML webhook: {str(e)}")
            # Return basic TwiML even on error
            response = VoiceResponse()
            response.say("Hello from webhook")
            return HttpResponse(str(response), content_type='application/xml')
    
    def get(self, request):
        """Handle GET requests for TwiML"""
        return self.post(request)

class AccessTokenView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Generate access token for Twilio Voice SDK"""
        identity = f"user_{request.user.id}"
        
        twilio_service = TwilioService()
        result = twilio_service.generate_access_token(identity)
        
        if result['success']:
            return Response({
                'token': result['token'],
                'identity': identity
            })
        else:
            return Response(
                {'error': result['error']}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )