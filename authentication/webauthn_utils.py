from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)
from django.conf import settings
from .models import WebAuthnCredential
import base64
import json
import secrets

class WebAuthnUtils:
    def __init__(self):
        self.rp_id = settings.PASSKEYS.get('RELYING_PARTY_ID', 'localhost')
        self.rp_name = settings.PASSKEYS.get('RELYING_PARTY_NAME', 'Internal Dashboard')
        
        # Determine origin based on environment
        if self.rp_id == 'localhost':
            self.origin = f"http://{self.rp_id}:3000"
        else:
            self.origin = f"https://{self.rp_id}"
    
    def _base64url_decode(self, data):
        """Decode base64url string to bytes with proper padding"""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)
        
    def generate_registration_options(self, user):
        """Generate registration options for a user"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=str(user.id).encode(),
                user_name=user.username,
                user_display_name=user.get_full_name() or user.username,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.PREFERRED
                )
            )
            
            logger.debug(f"Generated registration options for user {user.username}")
            
            # Store challenge in session
            session_key = f"webauthn_reg_state_{user.id}"
            challenge_b64 = base64.b64encode(options.challenge).decode()
            
            # Convert options to dict for JSON serialization
            options_dict = {
                'rp': {'name': self.rp_name, 'id': self.rp_id},
                'user': {
                    'id': base64.urlsafe_b64encode(str(user.id).encode()).decode().rstrip('='),
                    'name': user.username,
                    'displayName': user.get_full_name() or user.username
                },
                'challenge': base64.urlsafe_b64encode(options.challenge).decode().rstrip('='),
                'pubKeyCredParams': [{'type': 'public-key', 'alg': alg} for alg in [-7, -8, -35, -36, -37, -257, -47]],
                'authenticatorSelection': {
                    'residentKey': 'discouraged',
                    'userVerification': 'preferred',
                    'requireResidentKey': False
                },
                'attestation': 'none'
            }
            
            return {
                'publicKey': options_dict,
                'session_key': session_key,
                'state': challenge_b64
            }
            
        except Exception as e:
            logger.error(f"Error generating registration options: {e}")
            raise
    
    def verify_registration(self, attestation_response, user, state):
        """Verify registration response"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            logger.debug(f"Verifying registration for user: {user.username}")
            logger.debug(f"Attestation response keys: {list(attestation_response.keys())}")
            logger.debug(f"Attestation response: {attestation_response}")
            
            # Decode challenge
            challenge = base64.b64decode(state)
            
            # Handle both nested and flattened response formats
            if 'response' in attestation_response:
                # Nested format from frontend
                response_data = {
                    'clientDataJSON': attestation_response['response']['clientDataJSON'],
                    'attestationObject': attestation_response['response']['attestationObject']
                }
            else:
                # Flattened format from WebAuthnAdapter
                response_data = {
                    'clientDataJSON': attestation_response['clientDataJSON'],
                    'attestationObject': attestation_response['attestationObject']
                }
            
            # Convert base64url strings to bytes
            raw_id_bytes = self._base64url_decode(attestation_response['rawId'])
            client_data_json_bytes = self._base64url_decode(response_data['clientDataJSON'])
            attestation_object_bytes = self._base64url_decode(response_data['attestationObject'])
            
            logger.debug(f"Converted to bytes - raw_id: {len(raw_id_bytes)} bytes")
            logger.debug(f"client_data_json: {len(client_data_json_bytes)} bytes")
            logger.debug(f"attestation_object: {len(attestation_object_bytes)} bytes")
            
            # Create a response object with the correct attributes
            class AuthenticatorAttestationResponse:
                def __init__(self, client_data_json, attestation_object):
                    self.client_data_json = client_data_json
                    self.attestation_object = attestation_object
            
            response_obj = AuthenticatorAttestationResponse(
                client_data_json=client_data_json_bytes,
                attestation_object=attestation_object_bytes
            )
            
            logger.debug(f"Created response object with attributes: {dir(response_obj)}")
            
            # Create RegistrationCredential object
            credential = RegistrationCredential(
                id=attestation_response['id'],
                raw_id=raw_id_bytes,
                response=response_obj,
                type=attestation_response.get('type', 'public-key')
            )
            
            logger.debug(f"Created credential object: {credential.id}")
            logger.debug(f"About to call verify_registration_response...")
            
            # Verify the registration
            logger.debug(f"Calling verify_registration_response with:")
            logger.debug(f"  credential.id: {credential.id}")
            logger.debug(f"  expected_challenge: {len(challenge)} bytes")
            logger.debug(f"  expected_origin: {self.origin}")
            logger.debug(f"  expected_rp_id: {self.rp_id}")
            
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=self.origin,
                expected_rp_id=self.rp_id
            )
            
            logger.debug(f"Verification object: {verification}")
            logger.debug(f"Verification attributes: {dir(verification)}")
            
            # The webauthn library returns a VerifiedRegistration object
            # which doesn't have a 'verified' attribute - if it returns without error, it's verified
            logger.debug("Registration verification successful")
            
            # Store the credential
            # Convert credential_id to base64 string for storage
            if isinstance(verification.credential_id, bytes):
                credential_id_str = base64.b64encode(verification.credential_id).decode()
            else:
                credential_id_str = verification.credential_id
            
            webauthn_credential = WebAuthnCredential.objects.create(
                user=user,
                credential_id=credential_id_str,
                public_key=base64.b64encode(verification.credential_public_key).decode(),
                sign_count=verification.sign_count
            )
            
            logger.debug(f"Stored credential with ID: {webauthn_credential.credential_id}")
            return webauthn_credential
                
        except Exception as e:
            logger.error(f"Registration verification error: {e}")
            import traceback
            traceback.print_exc()
            raise ValueError(f"Registration verification failed: {str(e)}")
    
    def generate_authentication_options(self, user):
        """Generate authentication options for a user"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Get user's credentials
            credentials = []
            for cred in WebAuthnCredential.objects.filter(user=user):
                try:
                    # The credential_id is stored as base64-encoded string
                    # We need to decode it back to bytes for the webauthn library
                    credential_id_bytes = base64.b64decode(cred.credential_id)
                    credentials.append(credential_id_bytes)
                    logger.debug(f"Added credential: {cred.credential_id} -> {len(credential_id_bytes)} bytes")
                except Exception as e:
                    logger.warning(f"Error processing credential {cred.id}: {e}")
            
            options = generate_authentication_options(
                rp_id=self.rp_id,
                allow_credentials=credentials,
                user_verification=UserVerificationRequirement.PREFERRED
            )
            
            logger.debug(f"Generated authentication options for user {user.username}")
            
            # Store challenge in session
            session_key = f"webauthn_auth_state_{user.id}"
            challenge_b64 = base64.b64encode(options.challenge).decode()
            
            # Convert options to dict for JSON serialization
            options_dict = {
                'challenge': base64.urlsafe_b64encode(options.challenge).decode().rstrip('='),
                'allowCredentials': [
                    {
                        'id': base64.urlsafe_b64encode(cred_id).decode().rstrip('='),
                        'type': 'public-key',
                        'transports': ['internal']
                    } for cred_id in credentials
                ],
                'userVerification': 'preferred',
                'timeout': 60000
            }
            
            logger.debug(f"Generated {len(credentials)} allowCredentials for user {user.username}")
            
            return {
                'publicKey': options_dict,
                'session_key': session_key,
                'state': challenge_b64
            }
            
        except Exception as e:
            logger.error(f"Error generating authentication options: {e}")
            raise
    
    def verify_authentication(self, assertion_response, user, state):
        """Verify authentication response"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            logger.debug(f"Verifying authentication for user: {user.username}")
            
            # Decode challenge
            challenge = base64.b64decode(state)
            
            # Get credential from database
            credential_id = assertion_response['id']
            logger.debug(f"Looking for credential with ID: {credential_id}")
            
            # Find the credential by comparing the credential IDs
            webauthn_credential = None
            credential_id_bytes = self._base64url_decode(credential_id)
            credential_id_b64 = base64.b64encode(credential_id_bytes).decode()
            
            logger.debug(f"Looking for credential with base64 ID: {credential_id_b64}")
            
            for cred in WebAuthnCredential.objects.filter(user=user):
                logger.debug(f"Comparing with stored credential: {cred.credential_id}")
                if cred.credential_id == credential_id_b64:
                    webauthn_credential = cred
                    break
            
            if not webauthn_credential:
                raise ValueError("Credential not found")
            
            logger.debug(f"Found credential: {webauthn_credential.credential_id}")
            
            # Handle both nested and flattened response formats
            if 'response' in assertion_response:
                response_data = {
                    'clientDataJSON': assertion_response['response']['clientDataJSON'],
                    'authenticatorData': assertion_response['response']['authenticatorData'],
                    'signature': assertion_response['response']['signature'],
                    'userHandle': assertion_response['response'].get('userHandle')
                }
            else:
                response_data = {
                    'clientDataJSON': assertion_response['clientDataJSON'],
                    'authenticatorData': assertion_response['authenticatorData'],
                    'signature': assertion_response['signature'],
                    'userHandle': assertion_response.get('userHandle')
                }
            
            # Convert base64url strings to bytes
            raw_id_bytes = self._base64url_decode(assertion_response['rawId'])
            client_data_json_bytes = self._base64url_decode(response_data['clientDataJSON'])
            authenticator_data_bytes = self._base64url_decode(response_data['authenticatorData'])
            signature_bytes = self._base64url_decode(response_data['signature'])
            user_handle_bytes = self._base64url_decode(response_data['userHandle']) if response_data['userHandle'] else None
            
            # Create a response object with the correct attributes
            class AuthenticatorAssertionResponse:
                def __init__(self, client_data_json, authenticator_data, signature, user_handle):
                    self.client_data_json = client_data_json
                    self.authenticator_data = authenticator_data
                    self.signature = signature
                    self.user_handle = user_handle
            
            response_obj = AuthenticatorAssertionResponse(
                client_data_json=client_data_json_bytes,
                authenticator_data=authenticator_data_bytes,
                signature=signature_bytes,
                user_handle=user_handle_bytes
            )
            
            # Create AuthenticationCredential object
            credential = AuthenticationCredential(
                id=assertion_response['id'],
                raw_id=raw_id_bytes,
                response=response_obj,
                type=assertion_response.get('type', 'public-key')
            )
            
            logger.debug(f"Created authentication credential: {credential.id}")
            
            # Verify the authentication
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
                credential_public_key=base64.b64decode(webauthn_credential.public_key),
                credential_current_sign_count=webauthn_credential.sign_count
            )
            
            # The webauthn library returns a VerifiedAuthentication object
            # If it returns without error, it's verified
            logger.debug("Authentication verification successful")
            
            # Update sign count
            webauthn_credential.sign_count = verification.new_sign_count
            webauthn_credential.save()
            
            return {
                'success': True,
                'counter': verification.new_sign_count
            }
                
        except Exception as e:
            logger.error(f"Authentication verification error: {e}")
            import traceback
            traceback.print_exc()
            raise ValueError(f"Authentication verification failed: {str(e)}")