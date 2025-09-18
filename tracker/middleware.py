import logging
import traceback
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class GlobalExceptionMiddleware(MiddlewareMixin):
    """
    Global exception middleware to catch unhandled exceptions
    and return consistent error responses
    """
    
    def process_exception(self, request, exception):
        """
        Process unhandled exceptions and return a consistent error response
        """
        # Log the exception with full traceback
        logger.error(
            f"Unhandled exception in {request.method} {request.path}: {str(exception)}",
            exc_info=True,
            extra={
                'request_method': request.method,
                'request_path': request.path,
                'request_user': getattr(request.user, 'id', 'Anonymous') if hasattr(request, 'user') else 'Unknown',
                'request_data': getattr(request, 'data', None) if hasattr(request, 'data') else None,
            }
        )
        
        # Return a consistent error response
        return JsonResponse({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred on the server',
            'type': 'unhandled_exception',
            'details': str(exception) if settings.DEBUG else 'Please try again later'
        }, status=500)

# Django settings.py should include this middleware in MIDDLEWARE list:
# 'tracker.middleware.GlobalExceptionMiddleware',