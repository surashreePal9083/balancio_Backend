from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from django.http import Http404
from rest_framework.exceptions import NotFound, PermissionDenied
import logging

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    Custom exception handler for Django REST Framework
    Provides consistent error response format across all endpoints
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    # Log the exception for debugging
    logger.error(f"API Exception: {exc}", exc_info=True)
    
    # Handle different types of exceptions
    if isinstance(exc, ValidationError):
        # Handle Django validation errors
        return Response({
            'error': 'Validation Error',
            'message': 'The provided data is invalid',
            'details': exc.message_dict if hasattr(exc, 'message_dict') else str(exc),
            'type': 'validation_error'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    elif isinstance(exc, Http404) or isinstance(exc, NotFound):
        # Handle 404 errors
        return Response({
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'type': 'not_found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    elif isinstance(exc, PermissionDenied):
        # Handle permission errors
        return Response({
            'error': 'Permission Denied',
            'message': 'You do not have permission to perform this action',
            'type': 'permission_denied'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Handle DRF exceptions with custom formatting
    if response is not None:
        # Handle validation errors from serializers
        if response.status_code == 400:
            return Response({
                'error': 'Bad Request',
                'message': 'The request data is invalid',
                'details': response.data,
                'type': 'validation_error'
            }, status=response.status_code)
        
        # Handle authentication errors
        elif response.status_code == 401:
            return Response({
                'error': 'Unauthorized',
                'message': 'Authentication credentials were not provided or are invalid',
                'type': 'authentication_error'
            }, status=response.status_code)
        
        # Handle permission errors
        elif response.status_code == 403:
            return Response({
                'error': 'Forbidden',
                'message': 'You do not have permission to perform this action',
                'type': 'permission_error'
            }, status=response.status_code)
        
        # Handle not found errors
        elif response.status_code == 404:
            return Response({
                'error': 'Not Found',
                'message': 'The requested resource was not found',
                'type': 'not_found'
            }, status=response.status_code)
        
        # Handle method not allowed
        elif response.status_code == 405:
            return Response({
                'error': 'Method Not Allowed',
                'message': 'The HTTP method is not allowed for this endpoint',
                'type': 'method_not_allowed'
            }, status=response.status_code)
        
        # Handle server errors
        elif response.status_code >= 500:
            return Response({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred on the server',
                'type': 'server_error'
            }, status=response.status_code)
    
    # Handle uncaught exceptions
    if response is None:
        return Response({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'type': 'unhandled_exception'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return response