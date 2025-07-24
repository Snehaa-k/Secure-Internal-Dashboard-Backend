from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from .webauthn_utils import WebAuthnUtils
from .serializers import UserSerializer, RegisterSerializer, LoginSerializer

import logging
logger = logging.getLogger(__name__)

class RegisterOptionsView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"RegisterOptionsView received request: {request.data}")
        
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"RegisterOptionsView validation error: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        username = serializer.validated_data['username']
        logger.debug(f"Processing registration for username: {username}")
        
        # Check if user exists
        if User.objects.filter(username=username).exists():
            logger.warning(f"Username already exists: {username}")
            return Response(
                {"error": "Username already exists"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create a new user
        user = User.objects.create(username=username)
        logger.debug(f"Created new user with ID: {user.id}")
        
        # Get registration options
        webauthn = WebAuthnUtils()
        options = webauthn.generate_registration_options(user)
        logger.debug(f"Generated registration options: {options['publicKey']}")
        
        # Store state in session
        request.session[options['session_key']] = options['state']
        request.session.save()
        logger.debug(f"Stored state in session with key: {options['session_key']}")
        
        # Return options to client
        return Response(options['publicKey'])

class RegisterVerifyView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"RegisterVerifyView received request: {request.data}")
        
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"RegisterVerifyView validation error: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        username = serializer.validated_data['username']
        logger.debug(f"Verifying registration for username: {username}")
        
        user = get_object_or_404(User, username=username)
        
        # Get state from session
        session_key = f"webauthn_reg_state_{user.id}"
        logger.debug(f"Looking for session key: {session_key}")
        logger.debug(f"Available session keys: {list(request.session.keys())}")
        logger.debug(f"Session ID: {request.session.session_key}")
        
        state = request.session.get(session_key)
        
        if not state:
            logger.error(f"Registration session expired for user: {user.id}")
            logger.error(f"Session key not found: {session_key}")
            logger.error(f"Available keys: {list(request.session.keys())}")
            return Response(
                {"error": "Registration session expired"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.debug(f"Found session state for key: {session_key}")
        
        # Verify registration
        try:
            logger.debug(f"Verifying attestation response for user: {user.id}")
            webauthn = WebAuthnUtils()
            # Get the attestation response directly
            attestation_response = request.data.get('attestationResponse')
            logger.debug(f"Raw attestation response: {attestation_response}")
            
            # Verify registration
            credential_data = webauthn.verify_registration(
                attestation_response, 
                user,
                state
            )
            logger.debug(f"Successfully verified registration for user: {user.id}")
            
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            
            # Clear session data
            if session_key in request.session:
                del request.session[session_key]
                request.session.save()
                logger.debug(f"Cleared session data for key: {session_key}")
            
            return Response({
                'success': True,
                'token': str(refresh.access_token),
                'user': UserSerializer(user).data
            })
        except Exception as e:
            logger.error(f"Registration verification failed: {str(e)}")
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class LoginOptionsView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"LoginOptionsView received request: {request.data}")
        
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"LoginOptionsView validation error: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        username = serializer.validated_data['username']
        logger.debug(f"Processing login for username: {username}")
        
        user = get_object_or_404(User, username=username)
        
        # Get authentication options
        webauthn = WebAuthnUtils()
        options = webauthn.generate_authentication_options(user)
        logger.debug(f"Generated authentication options: {options['publicKey']}")
        
        # Store state in session
        request.session[options['session_key']] = options['state']
        request.session.save()
        logger.debug(f"Stored state in session with key: {options['session_key']}")
        
        # Return options to client
        return Response(options['publicKey'])

class LoginVerifyView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        logger.debug(f"LoginVerifyView received request: {request.data}")
        
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"LoginVerifyView validation error: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        username = serializer.validated_data['username']
        logger.debug(f"Verifying login for username: {username}")
        
        user = get_object_or_404(User, username=username)
        
        # Get state from session
        session_key = f"webauthn_auth_state_{user.id}"
        state = request.session.get(session_key)
        
        if not state:
            logger.error(f"Authentication session expired for user: {user.id}")
            return Response(
                {"error": "Authentication session expired"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify authentication
        try:
            logger.debug(f"Verifying assertion response for user: {user.id}")
            webauthn = WebAuthnUtils()
            # Get the assertion response directly
            assertion_response = request.data.get('assertionResponse')
            logger.debug(f"Raw assertion response: {assertion_response}")
            
            # Verify authentication
            auth_result = webauthn.verify_authentication(
                assertion_response, 
                user,
                state
            )
            logger.debug(f"Successfully verified authentication for user: {user.id}")
            
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            
            # Clear session data
            if session_key in request.session:
                del request.session[session_key]
                request.session.save()
                logger.debug(f"Cleared session data for key: {session_key}")
            
            return Response({
                'success': True,
                'token': str(refresh.access_token),
                'user': UserSerializer(user).data
            })
        except Exception as e:
            logger.error(f"Authentication verification failed: {str(e)}")
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class ValidateTokenView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        logger.debug(f"ValidateTokenView called for user: {request.user.username}")
        return Response({
            'valid': True,
            'user': UserSerializer(request.user).data
        })