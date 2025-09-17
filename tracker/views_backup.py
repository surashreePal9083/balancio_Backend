from django.contrib.auth import authenticate, login, logout
from django.db.models import Q, Sum
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status, generics, filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
from datetime import datetime, timedelta
from decimal import Decimal
import json
import csv
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model

from .models import User, Transaction, Category, Notification, Budget, BudgetAlert, MonthlyReport
from .serializers import (
    UserSerializer, UserProfileSerializer, UserSettingsSerializer, ChangePasswordSerializer,
    LoginSerializer, RegisterSerializer, CategorySerializer, TransactionSerializer,
    BudgetSerializer, BudgetAlertSerializer, NotificationSerializer, MonthlyReportSerializer
)

# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@swagger_auto_schema(
    method='post',
    operation_description="Authenticate a user with email and password",
    operation_summary="User login",
    tags=['Authentication'],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password')
        },
        required=['email', 'password']
    ),
    responses={
        200: openapi.Response(
            description="Login successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                            'email': openapi.Schema(type=openapi.TYPE_STRING)
                        }
                    ),
                    'access': openapi.Schema(type=openapi.TYPE_STRING, description='JWT access token'),
                    'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='JWT refresh token')
                }
            )
        ),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Invalid credentials")
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def auth_login(request: Request) -> Response:
    """User login endpoint"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'message': 'Login successful!',
            'user': {
                'id': user.pk,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email
            },
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Register a new user account",
    operation_summary="User registration",
    tags=['Authentication'],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
            'email': openapi.Schema(type=openapi.TYPE_STRING),
            'password': openapi.Schema(type=openapi.TYPE_STRING),
            'confirm_password': openapi.Schema(type=openapi.TYPE_STRING)
        },
        required=['first_name', 'last_name', 'email', 'password', 'confirm_password']
    ),
    responses={
        201: openapi.Response(description="User created successfully"),
        400: openapi.Response(description="Bad request")
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def auth_signup(request: Request) -> Response:
    """User registration endpoint"""
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'message': 'User created successfully!',
            'user': {
                'id': user.pk,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email
            }
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Google OAuth authentication (placeholder)",
    operation_summary="Google OAuth",
    tags=['Authentication'],
    responses={
        200: openapi.Response(description="Google auth successful"),
        400: openapi.Response(description="Bad request")
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def auth_google(request: Request) -> Response:
    """Google OAuth authentication endpoint (placeholder for future implementation)"""
    return Response({
        'message': 'Google OAuth not implemented yet',
        'status': 'coming_soon'
    }, status=status.HTTP_501_NOT_IMPLEMENTED)

@swagger_auto_schema(
    method='post',
    operation_description="GitHub OAuth authentication (placeholder)",
    operation_summary="GitHub OAuth",
    tags=['Authentication'],
    responses={
        200: openapi.Response(description="GitHub auth successful"),
        400: openapi.Response(description="Bad request")
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def auth_github(request: Request) -> Response:
    """GitHub OAuth authentication endpoint (placeholder for future implementation)"""
    return Response({
        'message': 'GitHub OAuth not implemented yet',
        'status': 'coming_soon'
    }, status=status.HTTP_501_NOT_IMPLEMENTED)

@swagger_auto_schema(
    method='post',
    operation_description="Logout the authenticated user",
    operation_summary="User logout",
    tags=['Authentication'],
    responses={
        200: openapi.Response(description="Logout successful"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def auth_logout(request: Request) -> Response:
    """User logout endpoint"""
    try:
        logout(request)
        return Response({'message': 'Logout successful!'})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# =============================================================================
# ENHANCED TRANSACTION ENDPOINTS
# =============================================================================

class TransactionPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

@swagger_auto_schema(
    method='get',
    operation_description="Get all transactions with filtering and pagination",
    operation_summary="List transactions (Enhanced)",
    tags=['Transactions'],
    manual_parameters=[
        openapi.Parameter('type', openapi.IN_QUERY, description="Filter by type (income/expense)", type=openapi.TYPE_STRING),
        openapi.Parameter('category', openapi.IN_QUERY, description="Filter by category ID", type=openapi.TYPE_INTEGER),
        openapi.Parameter('start_date', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('end_date', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search in title and description", type=openapi.TYPE_STRING),
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Items per page", type=openapi.TYPE_INTEGER),
    ],
    responses={
        200: openapi.Response(description="Paginated list of transactions"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def transactions_enhanced(request: Request) -> Response:
    """Enhanced transaction list with filtering and pagination"""
    queryset = Transaction.objects.filter(user=request.user)
    
    # Filtering
    transaction_type = request.query_params.get('type')
    if transaction_type:
        queryset = queryset.filter(type=transaction_type)
    
    category_id = request.query_params.get('category')
    if category_id:
        queryset = queryset.filter(category_id=category_id)
    
    start_date = request.query_params.get('start_date')
    if start_date:
        queryset = queryset.filter(date__gte=start_date)
    
    end_date = request.query_params.get('end_date')
    if end_date:
        queryset = queryset.filter(date__lte=end_date)
    
    search = request.query_params.get('search')
    if search:
        queryset = queryset.filter(
            Q(title__icontains=search) | Q(description__icontains=search)
        )
    
    # Pagination
    paginator = TransactionPagination()
    page = paginator.paginate_queryset(queryset, request)
    if page is not None:
        serializer = TransactionSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
    
    serializer = TransactionSerializer(queryset, many=True)
    return Response(serializer.data)

@swagger_auto_schema(
    method='get',
    operation_description="Get a specific transaction by ID",
    operation_summary="Get transaction by ID",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction details"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='put',
    operation_description="Update a specific transaction",
    operation_summary="Update transaction",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction updated"),
        404: openapi.Response(description="Transaction not found"),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='delete',
    operation_description="Delete a specific transaction",
    operation_summary="Delete transaction",
    tags=['Transactions'],
    responses={
        204: openapi.Response(description="Transaction deleted"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def transaction_detail(request: Request, transaction_id: int) -> Response:
    """Get, update, or delete a specific transaction"""
    try:
        transaction = Transaction.objects.get(id=transaction_id, user=request.user)
    except Transaction.DoesNotExist:
        return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = TransactionSerializer(transaction)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = TransactionSerializer(transaction, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        transaction.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# =============================================================================
# USER PROFILE AND SETTINGS ENDPOINTS
# =============================================================================

@swagger_auto_schema(
    method='get',
    operation_description="Get user profile information",
    operation_summary="Get user profile",
    tags=['Users'],
    responses={
        200: openapi.Response(description="User profile data"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='put',
    operation_description="Update user profile information",
    operation_summary="Update user profile",
    tags=['Users'],
    responses={
        200: openapi.Response(description="Profile updated successfully"),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def users_profile(request: Request) -> Response:
    """Get or update user profile"""
    if request.method == 'GET':
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully!',
                'user': serializer.data
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@swagger_auto_schema(
    method='post',
    operation_description="Change user password",
    operation_summary="Change password",
    tags=['Users'],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'old_password': openapi.Schema(type=openapi.TYPE_STRING),
            'new_password': openapi.Schema(type=openapi.TYPE_STRING),
            'confirm_password': openapi.Schema(type=openapi.TYPE_STRING)
        },
        required=['old_password', 'new_password', 'confirm_password']
    ),
    responses={
        200: openapi.Response(description="Password changed successfully"),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def users_change_password(request: Request) -> Response:
    """Change user password"""
    serializer = ChangePasswordSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        
        # Check old password
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({'error': 'Old password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Set new password
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        return Response({'message': 'Password changed successfully!'})
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    operation_description="Get user settings",
    operation_summary="Get user settings",
    tags=['Users'],
    responses={
        200: openapi.Response(description="User settings data"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='put',
    operation_description="Update user settings",
    operation_summary="Update user settings",
    tags=['Users'],
    responses={
        200: openapi.Response(description="Settings updated successfully"),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def users_settings(request: Request) -> Response:
    """Get or update user settings"""
    if request.method == 'GET':
        serializer = UserSettingsSerializer(request.user)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = UserSettingsSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Settings updated successfully!',
                'settings': serializer.data
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

transaction_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Transaction ID'),
        'title': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction title'),
        'amount': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction amount'),
        'type': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction type'),
        'category': openapi.Schema(type=openapi.TYPE_STRING, description='Category name'),
        'description': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction description'),
        'date': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction date'),
        'created_at': openapi.Schema(type=openapi.TYPE_STRING, description='Creation timestamp')
    }
)

category_request_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'name': openapi.Schema(type=openapi.TYPE_STRING, description='Category name'),
        'type': openapi.Schema(type=openapi.TYPE_STRING, description='Category type (income/expense)', enum=['income', 'expense']),
        'color': openapi.Schema(type=openapi.TYPE_STRING, description='Category color (hex code, optional)'),
        'icon': openapi.Schema(type=openapi.TYPE_STRING, description='Category icon (optional)')
    },
    required=['name', 'type']
)

category_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Category ID'),
        'name': openapi.Schema(type=openapi.TYPE_STRING, description='Category name'),
        'type': openapi.Schema(type=openapi.TYPE_STRING, description='Category type'),
        'color': openapi.Schema(type=openapi.TYPE_STRING, description='Category color'),
        'icon': openapi.Schema(type=openapi.TYPE_STRING, description='Category icon')
    }
)

login_request_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password')
    },
    required=['email', 'password']
)

login_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
        'user': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='User ID'),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='First name'),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Last name'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email')
            }
        ),
        'access': openapi.Schema(type=openapi.TYPE_STRING, description='JWT access token'),
        'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='JWT refresh token')
    }
)

register_request_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='First name'),
        'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Last name'),
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
        'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, description='Confirm password')
    },
    required=['first_name', 'last_name', 'email', 'password', 'confirm_password']
)

error_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'error': openapi.Schema(type=openapi.TYPE_STRING, description='Error message')
    }
)

# Get all transactions for a user
@swagger_auto_schema(
    method='get',
    operation_description="Retrieve all transactions for the authenticated user",
    operation_summary="List user transactions",
    tags=['Transactions'],
    responses={
        200: openapi.Response(
            description="List of transactions",
            schema=openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=transaction_response_schema
            )
        ),
        401: openapi.Response(description="Authentication required", schema=error_response_schema)
    }
)
@swagger_auto_schema(
    method='post',
    operation_description="Create a new transaction for the authenticated user",
    operation_summary="Create transaction",
    tags=['Transactions'],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'title': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction title'),
            'amount': openapi.Schema(type=openapi.TYPE_NUMBER, description='Transaction amount'),
            'type': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction type (income/expense)', enum=['income', 'expense']),
            'category': openapi.Schema(type=openapi.TYPE_INTEGER, description='Category ID (optional)'),
            'description': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction description (optional)'),
            'date': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction date (ISO format, optional)')  
        },
        required=['title', 'amount', 'type']
    ),
    responses={
        201: openapi.Response(
            description="Transaction created successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Transaction ID'),
                    'title': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction title'),
                    'amount': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction amount'),
                    'type': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction type'),
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message')
                }
            )
        ),
        400: openapi.Response(description="Bad request", schema=error_response_schema),
        401: openapi.Response(description="Authentication required", schema=error_response_schema)
    }
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def transaction_list(request: Request) -> Response:
    if request.method == 'GET':
        transactions = Transaction.objects.filter(user=request.user)
        data = []
        for transaction in transactions:
            data.append({
                'id': transaction.pk,
                'title': transaction.title,
                'amount': str(transaction.amount),
                'type': transaction.type,
                'category': transaction.category.name if transaction.category else None,
                'description': transaction.description,
                'date': transaction.date.isoformat(),
                'created_at': transaction.created_at.isoformat()
            })
        return Response(data)
    
    elif request.method == 'POST':
        data = request.data
        try:
            category = None
            if data.get('category_id'):
                category = Category.objects.get(id=data['category_id'], user=request.user)
            
            transaction = Transaction.objects.create(
                user=request.user,
                title=data['title'],
                amount=data['amount'],
                type=data['type'],
                category=category,
                description=data.get('description', ''),
                date=datetime.fromisoformat(data.get('date', datetime.now().isoformat()))
            )
            
            return Response({
                'id': transaction.pk,
                'title': transaction.title,
                'amount': str(transaction.amount),
                'type': transaction.type,
                'message': 'Transaction created successfully!'
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# =============================================================================
# ENHANCED TRANSACTION ENDPOINTS
# =============================================================================

class TransactionPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

@swagger_auto_schema(
    method='get',
    operation_description="Get all transactions with filtering and pagination",
    operation_summary="List transactions (Enhanced)",
    tags=['Transactions'],
    manual_parameters=[
        openapi.Parameter('type', openapi.IN_QUERY, description="Filter by type (income/expense)", type=openapi.TYPE_STRING),
        openapi.Parameter('category', openapi.IN_QUERY, description="Filter by category ID", type=openapi.TYPE_INTEGER),
        openapi.Parameter('start_date', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('end_date', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search in title and description", type=openapi.TYPE_STRING),
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Items per page", type=openapi.TYPE_INTEGER),
    ],
    responses={
        200: openapi.Response(description="Paginated list of transactions"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def transactions_enhanced(request: Request) -> Response:
    """Enhanced transaction list with filtering and pagination"""
    queryset = Transaction.objects.filter(user=request.user)
    
    # Filtering
    transaction_type = request.query_params.get('type')
    if transaction_type:
        queryset = queryset.filter(type=transaction_type)
    
    category_id = request.query_params.get('category')
    if category_id:
        queryset = queryset.filter(category_id=category_id)
    
    start_date = request.query_params.get('start_date')
    if start_date:
        queryset = queryset.filter(date__gte=start_date)
    
    end_date = request.query_params.get('end_date')
    if end_date:
        queryset = queryset.filter(date__lte=end_date)
    
    search = request.query_params.get('search')
    if search:
        queryset = queryset.filter(
            Q(title__icontains=search) | Q(description__icontains=search)
        )
    
    # Pagination
    paginator = TransactionPagination()
    page = paginator.paginate_queryset(queryset, request)
    if page is not None:
        serializer = TransactionSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
    
    serializer = TransactionSerializer(queryset, many=True)
    return Response(serializer.data)

@swagger_auto_schema(
    method='get',
    operation_description="Get a specific transaction by ID",
    operation_summary="Get transaction by ID",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction details"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='put',
    operation_description="Update a specific transaction",
    operation_summary="Update transaction",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction updated"),
        404: openapi.Response(description="Transaction not found"),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='delete',
    operation_description="Delete a specific transaction",
    operation_summary="Delete transaction",
    tags=['Transactions'],
    responses={
        204: openapi.Response(description="Transaction deleted"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def transaction_detail(request: Request, transaction_id: int) -> Response:
    """Get, update, or delete a specific transaction"""
    try:
        transaction = Transaction.objects.get(id=transaction_id, user=request.user)
    except Transaction.DoesNotExist:
        return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = TransactionSerializer(transaction)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = TransactionSerializer(transaction, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        transaction.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    # This should never be reached, but ensures all paths return Response
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Get all categories for a user
@swagger_auto_schema(
    method='get',
    operation_description="Retrieve all categories for the authenticated user",
    operation_summary="List user categories",
    tags=['Categories'],
    responses={
        200: openapi.Response(
            description="List of categories",
            schema=openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=category_response_schema
            )
        ),
        401: openapi.Response(description="Authentication required", schema=error_response_schema)
    }
)
@swagger_auto_schema(
    method='post',
    operation_description="Create a new category for the authenticated user",
    operation_summary="Create category",
    tags=['Categories'],
    request_body=category_request_schema,
    responses={
        201: openapi.Response(
            description="Category created successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Category ID'),
                    'name': openapi.Schema(type=openapi.TYPE_STRING, description='Category name'),
                    'type': openapi.Schema(type=openapi.TYPE_STRING, description='Category type'),
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message')
                }
            )
        ),
        400: openapi.Response(description="Bad request", schema=error_response_schema),
        401: openapi.Response(description="Authentication required", schema=error_response_schema)
    }
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def category_list(request: Request) -> Response:
    if request.method == 'GET':
        categories = Category.objects.filter(user=request.user)
        data = []
        for category in categories:
            data.append({
                'id': category.pk,
                'name': category.name,
                'type': category.type,
                'color': category.color,
                'icon': category.icon
            })
        return Response(data)
    
    elif request.method == 'POST':
        data = request.data
        try:
            category = Category.objects.create(
                user=request.user,
                name=data['name'],
                type=data['type'],
                color=data.get('color', '#3B82F6'),
                icon=data.get('icon', 'category')
            )
            
            return Response({
                'id': category.pk,
                'name': category.name,
                'type': category.type,
                'message': 'Category created successfully!'
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# =============================================================================
# ENHANCED TRANSACTION ENDPOINTS
# =============================================================================

class TransactionPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

@swagger_auto_schema(
    method='get',
    operation_description="Get all transactions with filtering and pagination",
    operation_summary="List transactions (Enhanced)",
    tags=['Transactions'],
    manual_parameters=[
        openapi.Parameter('type', openapi.IN_QUERY, description="Filter by type (income/expense)", type=openapi.TYPE_STRING),
        openapi.Parameter('category', openapi.IN_QUERY, description="Filter by category ID", type=openapi.TYPE_INTEGER),
        openapi.Parameter('start_date', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('end_date', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search in title and description", type=openapi.TYPE_STRING),
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Items per page", type=openapi.TYPE_INTEGER),
    ],
    responses={
        200: openapi.Response(description="Paginated list of transactions"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def transactions_enhanced(request: Request) -> Response:
    """Enhanced transaction list with filtering and pagination"""
    queryset = Transaction.objects.filter(user=request.user)
    
    # Filtering
    transaction_type = request.query_params.get('type')
    if transaction_type:
        queryset = queryset.filter(type=transaction_type)
    
    category_id = request.query_params.get('category')
    if category_id:
        queryset = queryset.filter(category_id=category_id)
    
    start_date = request.query_params.get('start_date')
    if start_date:
        queryset = queryset.filter(date__gte=start_date)
    
    end_date = request.query_params.get('end_date')
    if end_date:
        queryset = queryset.filter(date__lte=end_date)
    
    search = request.query_params.get('search')
    if search:
        queryset = queryset.filter(
            Q(title__icontains=search) | Q(description__icontains=search)
        )
    
    # Pagination
    paginator = TransactionPagination()
    page = paginator.paginate_queryset(queryset, request)
    if page is not None:
        serializer = TransactionSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
    
    serializer = TransactionSerializer(queryset, many=True)
    return Response(serializer.data)

@swagger_auto_schema(
    method='get',
    operation_description="Get a specific transaction by ID",
    operation_summary="Get transaction by ID",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction details"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='put',
    operation_description="Update a specific transaction",
    operation_summary="Update transaction",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction updated"),
        404: openapi.Response(description="Transaction not found"),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='delete',
    operation_description="Delete a specific transaction",
    operation_summary="Delete transaction",
    tags=['Transactions'],
    responses={
        204: openapi.Response(description="Transaction deleted"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def transaction_detail(request: Request, transaction_id: int) -> Response:
    """Get, update, or delete a specific transaction"""
    try:
        transaction = Transaction.objects.get(id=transaction_id, user=request.user)
    except Transaction.DoesNotExist:
        return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = TransactionSerializer(transaction)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = TransactionSerializer(transaction, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        transaction.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    # This should never be reached, but ensures all paths return Response
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Simple login view
@swagger_auto_schema(
    method='post',
    operation_description="Authenticate a user with email and password",
    operation_summary="User login",
    tags=['Authentication'],
    request_body=login_request_schema,
    responses={
        200: openapi.Response(
            description="Login successful",
            schema=login_response_schema
        ),
        400: openapi.Response(description="Missing email or password", schema=error_response_schema),
        401: openapi.Response(description="Invalid credentials", schema=error_response_schema)
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request: Request) -> Response:
    email = request.data.get('email')
    password = request.data.get('password')
    
    if email and password:
        # Get user by email first
        try:
            user_obj = User.objects.get(email=email)
            # Authenticate using the username from the user object
            user = authenticate(request, username=user_obj.username, password=password)
            if user:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    'message': 'Login successful!',
                    'user': {
                        'id': user.pk,
                        'first_name': getattr(user, 'first_name', ''),
                        'last_name': getattr(user, 'last_name', ''),
                        'email': getattr(user, 'email', '')
                    },
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                })
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'Email and password required'}, status=status.HTTP_400_BAD_REQUEST)

# Simple logout view
@swagger_auto_schema(
    method='post',
    operation_description="Logout the authenticated user",
    operation_summary="User logout",
    tags=['Authentication'],
    responses={
        200: openapi.Response(
            description="Logout successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message')
                }
            )
        ),
        401: openapi.Response(description="Authentication required", schema=error_response_schema)
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request: Request) -> Response:
    logout(request)
    return Response({'message': 'Logout successful!'})

# User registration view
@swagger_auto_schema(
    method='post',
    operation_description="Register a new user account",
    operation_summary="User registration",
    tags=['Authentication'],
    request_body=register_request_schema,
    responses={
        201: openapi.Response(
            description="User created successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='User ID'),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='First name'),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Last name'),
                            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email')
                        }
                    )
                }
            )
        ),
        400: openapi.Response(description="Email already exists, passwords don't match, or invalid data", schema=error_response_schema)
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def user_register(request: Request) -> Response:
    data = request.data
    
    try:
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'email', 'password', 'confirm_password']
        for field in required_fields:
            if not data.get(field):
                return Response({'error': f'{field.replace("_", " ").title()} is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check password confirmation
        if data['password'] != data['confirm_password']:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if email already exists
        if User.objects.filter(email=data['email']).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate username from email (use email prefix)
        username = data['email'].split('@')[0]
        counter = 1
        original_username = username
        
        # Ensure username is unique
        while User.objects.filter(username=username).exists():
            username = f"{original_username}{counter}"
            counter += 1
        
        user = User.objects.create_user(
            username=username,
            email=data['email'],
            password=data['password'],
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        
        return Response({
            'message': 'User created successfully!',
            'user': {
                'id': user.pk,
                'first_name': getattr(user, 'first_name', ''),
                'last_name': getattr(user, 'last_name', ''),
                'email': getattr(user, 'email', '')
            }
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# =============================================================================
# ENHANCED TRANSACTION ENDPOINTS
# =============================================================================

class TransactionPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

@swagger_auto_schema(
    method='get',
    operation_description="Get all transactions with filtering and pagination",
    operation_summary="List transactions (Enhanced)",
    tags=['Transactions'],
    manual_parameters=[
        openapi.Parameter('type', openapi.IN_QUERY, description="Filter by type (income/expense)", type=openapi.TYPE_STRING),
        openapi.Parameter('category', openapi.IN_QUERY, description="Filter by category ID", type=openapi.TYPE_INTEGER),
        openapi.Parameter('start_date', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('end_date', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)", type=openapi.TYPE_STRING),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search in title and description", type=openapi.TYPE_STRING),
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Items per page", type=openapi.TYPE_INTEGER),
    ],
    responses={
        200: openapi.Response(description="Paginated list of transactions"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def transactions_enhanced(request: Request) -> Response:
    """Enhanced transaction list with filtering and pagination"""
    queryset = Transaction.objects.filter(user=request.user)
    
    # Filtering
    transaction_type = request.query_params.get('type')
    if transaction_type:
        queryset = queryset.filter(type=transaction_type)
    
    category_id = request.query_params.get('category')
    if category_id:
        queryset = queryset.filter(category_id=category_id)
    
    start_date = request.query_params.get('start_date')
    if start_date:
        queryset = queryset.filter(date__gte=start_date)
    
    end_date = request.query_params.get('end_date')
    if end_date:
        queryset = queryset.filter(date__lte=end_date)
    
    search = request.query_params.get('search')
    if search:
        queryset = queryset.filter(
            Q(title__icontains=search) | Q(description__icontains=search)
        )
    
    # Pagination
    paginator = TransactionPagination()
    page = paginator.paginate_queryset(queryset, request)
    if page is not None:
        serializer = TransactionSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
    
    serializer = TransactionSerializer(queryset, many=True)
    return Response(serializer.data)

@swagger_auto_schema(
    method='get',
    operation_description="Get a specific transaction by ID",
    operation_summary="Get transaction by ID",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction details"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='put',
    operation_description="Update a specific transaction",
    operation_summary="Update transaction",
    tags=['Transactions'],
    responses={
        200: openapi.Response(description="Transaction updated"),
        404: openapi.Response(description="Transaction not found"),
        400: openapi.Response(description="Bad request"),
        401: openapi.Response(description="Authentication required")
    }
)
@swagger_auto_schema(
    method='delete',
    operation_description="Delete a specific transaction",
    operation_summary="Delete transaction",
    tags=['Transactions'],
    responses={
        204: openapi.Response(description="Transaction deleted"),
        404: openapi.Response(description="Transaction not found"),
        401: openapi.Response(description="Authentication required")
    }
)
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def transaction_detail(request: Request, transaction_id: int) -> Response:
    """Get, update, or delete a specific transaction"""
    try:
        transaction = Transaction.objects.get(id=transaction_id, user=request.user)
    except Transaction.DoesNotExist:
        return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = TransactionSerializer(transaction)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = TransactionSerializer(transaction, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        transaction.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
