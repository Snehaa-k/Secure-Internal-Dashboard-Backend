import base64
import logging

logger = logging.getLogger(__name__)

class WebAuthnAdapter:
    """
    Adapter class to handle different WebAuthn response formats
    """
    
    @staticmethod
    def normalize_registration_response(attestation_response):
        """
        Normalize the registration response to a format expected by the WebAuthn library
        """
        logger.debug(f"Normalizing registration response: {attestation_response}")
        
        if not attestation_response:
            raise ValueError("No attestation response provided")
        
        normalized = {}
        
        # Copy basic properties
        normalized['id'] = attestation_response.get('id')
        normalized['rawId'] = attestation_response.get('rawId')
        normalized['type'] = attestation_response.get('type')
        
        # Handle nested response format
        if 'response' in attestation_response:
            response_data = attestation_response['response']
            
            # Process clientDataJSON
            if 'clientDataJSON' in response_data:
                try:
                    normalized['clientDataJSON'] = WebAuthnAdapter._decode_base64(response_data['clientDataJSON'])
                    logger.debug(f"Decoded clientDataJSON, length: {len(normalized['clientDataJSON'])}")
                except Exception as e:
                    logger.error(f"Error decoding clientDataJSON: {e}")
                    raise ValueError(f"Invalid clientDataJSON: {e}")
            else:
                logger.error("Missing clientDataJSON in response")
                raise ValueError("Missing clientDataJSON in response")
            
            # Process attestationObject
            if 'attestationObject' in response_data:
                try:
                    normalized['attestationObject'] = WebAuthnAdapter._decode_base64(response_data['attestationObject'])
                    logger.debug(f"Decoded attestationObject, length: {len(normalized['attestationObject'])}")
                except Exception as e:
                    logger.error(f"Error decoding attestationObject: {e}")
                    raise ValueError(f"Invalid attestationObject: {e}")
            else:
                logger.error("Missing attestationObject in response")
                raise ValueError("Missing attestationObject in response")
        
        # Handle direct format
        else:
            # Process clientDataJSON
            if 'clientDataJSON' in attestation_response:
                try:
                    normalized['clientDataJSON'] = WebAuthnAdapter._decode_base64(attestation_response['clientDataJSON'])
                    logger.debug(f"Decoded clientDataJSON, length: {len(normalized['clientDataJSON'])}")
                except Exception as e:
                    logger.error(f"Error decoding clientDataJSON: {e}")
                    raise ValueError(f"Invalid clientDataJSON: {e}")
            else:
                logger.error("Missing clientDataJSON in direct format")
                raise ValueError("Missing clientDataJSON in direct format")
            
            # Process attestationObject
            if 'attestationObject' in attestation_response:
                try:
                    normalized['attestationObject'] = WebAuthnAdapter._decode_base64(attestation_response['attestationObject'])
                    logger.debug(f"Decoded attestationObject, length: {len(normalized['attestationObject'])}")
                except Exception as e:
                    logger.error(f"Error decoding attestationObject: {e}")
                    raise ValueError(f"Invalid attestationObject: {e}")
            else:
                logger.error("Missing attestationObject in direct format")
                raise ValueError("Missing attestationObject in direct format")
        
        logger.debug("Normalized registration response ready for verification")
        return normalized
    
    @staticmethod
    def normalize_authentication_response(assertion_response):
        """
        Normalize the authentication response to a format expected by the WebAuthn library
        """
        logger.debug(f"Normalizing authentication response: {assertion_response}")
        
        if not assertion_response:
            raise ValueError("No assertion response provided")
        
        normalized = {}
        
        # Copy basic properties
        normalized['id'] = assertion_response.get('id')
        normalized['rawId'] = assertion_response.get('rawId')
        normalized['type'] = assertion_response.get('type')
        
        # Handle nested response format
        if 'response' in assertion_response:
            response_data = assertion_response['response']
            
            # Process clientDataJSON
            if 'clientDataJSON' in response_data:
                try:
                    normalized['clientDataJSON'] = WebAuthnAdapter._decode_base64(response_data['clientDataJSON'])
                    logger.debug(f"Decoded clientDataJSON, length: {len(normalized['clientDataJSON'])}")
                except Exception as e:
                    logger.error(f"Error decoding clientDataJSON: {e}")
                    raise ValueError(f"Invalid clientDataJSON: {e}")
            else:
                logger.error("Missing clientDataJSON in response")
                raise ValueError("Missing clientDataJSON in response")
            
            # Process authenticatorData
            if 'authenticatorData' in response_data:
                try:
                    normalized['authenticatorData'] = WebAuthnAdapter._decode_base64(response_data['authenticatorData'])
                    logger.debug(f"Decoded authenticatorData, length: {len(normalized['authenticatorData'])}")
                except Exception as e:
                    logger.error(f"Error decoding authenticatorData: {e}")
                    raise ValueError(f"Invalid authenticatorData: {e}")
            else:
                logger.error("Missing authenticatorData in response")
                raise ValueError("Missing authenticatorData in response")
            
            # Process signature
            if 'signature' in response_data:
                try:
                    normalized['signature'] = WebAuthnAdapter._decode_base64(response_data['signature'])
                    logger.debug(f"Decoded signature, length: {len(normalized['signature'])}")
                except Exception as e:
                    logger.error(f"Error decoding signature: {e}")
                    raise ValueError(f"Invalid signature: {e}")
            else:
                logger.error("Missing signature in response")
                raise ValueError("Missing signature in response")
            
            # Process userHandle if present
            if 'userHandle' in response_data and response_data['userHandle']:
                try:
                    normalized['userHandle'] = WebAuthnAdapter._decode_base64(response_data['userHandle'])
                    logger.debug(f"Decoded userHandle, length: {len(normalized['userHandle'])}")
                except Exception as e:
                    logger.error(f"Error decoding userHandle: {e}")
                    raise ValueError(f"Invalid userHandle: {e}")
        
        # Handle direct format
        else:
            # Process clientDataJSON
            if 'clientDataJSON' in assertion_response:
                try:
                    normalized['clientDataJSON'] = WebAuthnAdapter._decode_base64(assertion_response['clientDataJSON'])
                    logger.debug(f"Decoded clientDataJSON, length: {len(normalized['clientDataJSON'])}")
                except Exception as e:
                    logger.error(f"Error decoding clientDataJSON: {e}")
                    raise ValueError(f"Invalid clientDataJSON: {e}")
            else:
                logger.error("Missing clientDataJSON in direct format")
                raise ValueError("Missing clientDataJSON in direct format")
            
            # Process authenticatorData
            if 'authenticatorData' in assertion_response:
                try:
                    normalized['authenticatorData'] = WebAuthnAdapter._decode_base64(assertion_response['authenticatorData'])
                    logger.debug(f"Decoded authenticatorData, length: {len(normalized['authenticatorData'])}")
                except Exception as e:
                    logger.error(f"Error decoding authenticatorData: {e}")
                    raise ValueError(f"Invalid authenticatorData: {e}")
            else:
                logger.error("Missing authenticatorData in direct format")
                raise ValueError("Missing authenticatorData in direct format")
            
            # Process signature
            if 'signature' in assertion_response:
                try:
                    normalized['signature'] = WebAuthnAdapter._decode_base64(assertion_response['signature'])
                    logger.debug(f"Decoded signature, length: {len(normalized['signature'])}")
                except Exception as e:
                    logger.error(f"Error decoding signature: {e}")
                    raise ValueError(f"Invalid signature: {e}")
            else:
                logger.error("Missing signature in direct format")
                raise ValueError("Missing signature in direct format")
            
            # Process userHandle if present
            if 'userHandle' in assertion_response and assertion_response['userHandle']:
                try:
                    normalized['userHandle'] = WebAuthnAdapter._decode_base64(assertion_response['userHandle'])
                    logger.debug(f"Decoded userHandle, length: {len(normalized['userHandle'])}")
                except Exception as e:
                    logger.error(f"Error decoding userHandle: {e}")
                    raise ValueError(f"Invalid userHandle: {e}")
        
        logger.debug("Normalized authentication response ready for verification")
        return normalized
    
    @staticmethod
    def _decode_base64(base64_string):
        """
        Decode a base64 or base64url string to bytes
        """
        try:
            # Handle base64url encoding
            padded = base64_string.replace('-', '+').replace('_', '/')
            padding = len(padded) % 4
            if padding:
                padded += '=' * (4 - padding)
            
            return base64.b64decode(padded)
        except Exception as e:
            logger.error(f"Error decoding base64 string: {e}")
            raise ValueError(f"Invalid base64 string: {e}")