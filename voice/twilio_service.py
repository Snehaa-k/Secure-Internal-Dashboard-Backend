from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VoiceGrant
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class TwilioService:
    def __init__(self):
        self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        self.from_number = settings.TWILIO_PHONE_NUMBER
    
    def make_call(self, to_number, callback_url=None):
        """Initiate an outbound call"""
        try:
            call = self.client.calls.create(
                to=to_number,
                from_=self.from_number,
                url=callback_url or 'http://demo.twilio.com/docs/voice.xml',
                method='POST'
            )
            logger.info(f"Call initiated: {call.sid} to {to_number}")
            
            # Update last_contacted for the contact
            self.update_contact_last_contacted(to_number)
            
            return {
                'success': True,
                'call_sid': call.sid,
                'status': call.status,
                'to': to_number,
                'from': self.from_number
            }
        except Exception as e:
            logger.error(f"Failed to make call to {to_number}: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def hangup_call(self, call_sid):
        """End an active call"""
        try:
            call = self.client.calls(call_sid).update(status='completed')
            logger.info(f"Call {call_sid} ended")
            return {
                'success': True,
                'call_sid': call_sid,
                'status': call.status
            }
        except Exception as e:
            logger.error(f"Failed to hangup call {call_sid}: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_call_status(self, call_sid):
        """Get the status of a call"""
        try:
            call = self.client.calls(call_sid).fetch()
            return {
                'success': True,
                'call_sid': call_sid,
                'status': call.status,
                'duration': call.duration,
                'start_time': call.start_time,
                'end_time': call.end_time,
                'to': call.to,
                'from': call.from_formatted
            }
        except Exception as e:
            logger.error(f"Failed to get call status for {call_sid}: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_call_history(self, limit=50):
        """Get recent call history"""
        try:
            calls = self.client.calls.list(limit=limit)
            call_history = []
            
            for call in calls:
                call_history.append({
                    'call_sid': call.sid,
                    'to': call.to,
                    'from': call.from_formatted,
                    'status': call.status,
                    'duration': call.duration,
                    'start_time': call.start_time,
                    'end_time': call.end_time,
                    'direction': call.direction
                })
            
            return {
                'success': True,
                'calls': call_history
            }
        except Exception as e:
            logger.error(f"Failed to get call history: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def generate_twiml_response(self, message="Hello, this is a call from your dashboard."):
        """Generate TwiML response for incoming calls"""
        response = VoiceResponse()
        response.say(message)
        return str(response)
    
    def generate_access_token(self, identity):
        """Generate access token for Twilio Voice SDK"""
        try:
            # Check if all required settings are present
            if not all([
                settings.TWILIO_ACCOUNT_SID,
                settings.TWILIO_API_KEY_SID, 
                settings.TWILIO_API_KEY_SECRET,
                settings.TWILIO_TWIML_APP_SID
            ]):
                raise ValueError("Missing Twilio credentials. Please check your .env file.")
            
            # Create access token with 1 hour expiry
            token = AccessToken(
                settings.TWILIO_ACCOUNT_SID,
                settings.TWILIO_API_KEY_SID,
                settings.TWILIO_API_KEY_SECRET,
                identity=identity,
                ttl=3600  # 1 hour
            )
            
            # Create voice grant
            voice_grant = VoiceGrant(
                outgoing_application_sid=settings.TWILIO_TWIML_APP_SID,
                incoming_allow=True
            )
            
            # Add grant to token
            token.add_grant(voice_grant)
            
            logger.info(f"Generated access token for identity: {identity}")
            
            return {
                'success': True,
                'token': token.to_jwt()
            }
        except Exception as e:
            logger.error(f"Failed to generate access token: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def update_contact_last_contacted(self, phone_number):
        """Update last_contacted timestamp for a contact"""
        try:
            from contacts.models import Contact
            from django.utils import timezone
            
            contact = Contact.objects.filter(phone_number=phone_number).first()
            if contact:
                contact.last_contacted = timezone.now()
                contact.save()
                logger.info(f"Updated last_contacted for contact: {contact.name}")
        except Exception as e:
            logger.error(f"Failed to update last_contacted: {str(e)}")