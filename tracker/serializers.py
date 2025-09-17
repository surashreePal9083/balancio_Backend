from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from typing import Any, Dict, Union
from .models import User, Transaction, Category, Notification, Budget, BudgetAlert, MonthlyReport

# Type ignore for django-stubs compatibility issues
# pyright: reportIncompatibleVariableOverride=false
# pyright: reportArgumentType=false

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model - handles user data serialization"""
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'phone_number', 'date_of_birth', 'profile_picture', 'bio',
            'monthly_budget_amount', 'monthly_budget_currency',
            'budget_warning_threshold', 'budget_critical_threshold',
            'email_notifications', 'budget_alerts', 'monthly_reports',
            'preferred_currency', 'date_format_preference', 'timezone_preference',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'username', 'created_at', 'updated_at']
        extra_kwargs: Dict[str, Any] = {}

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile updates"""
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone_number', 'date_of_birth', 'profile_picture', 'bio',
            'preferred_currency', 'date_format_preference', 'timezone_preference'
        ]
        read_only_fields = ['id']
        extra_kwargs: Dict[str, Any] = {}

class UserSettingsSerializer(serializers.ModelSerializer):
    """Serializer for user settings updates"""
    
    class Meta:
        model = User
        fields = [
            'monthly_budget_amount', 'monthly_budget_currency',
            'budget_warning_threshold', 'budget_critical_threshold',
            'email_notifications', 'budget_alerts', 'monthly_reports',
            'preferred_currency', 'date_format_preference', 'timezone_preference'
        ]
        extra_kwargs: Dict[str, Any] = {}

class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change"""
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)
    
    def validate_new_password(self, value):
        validate_password(value)
        return value
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New passwords don't match")
        return attrs

class LoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    email = serializers.EmailField()
    password = serializers.CharField()
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            try:
                user_obj = User.objects.get(email=email)
                user = authenticate(username=user_obj.username, password=password)
                if not user:
                    raise serializers.ValidationError('Invalid credentials')
                if not user.is_active:
                    raise serializers.ValidationError('User account is disabled')
                attrs['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError('Invalid credentials')
        else:
            raise serializers.ValidationError('Email and password required')
        
        return attrs

class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']
        extra_kwargs: Dict[str, Any] = {}
    
    def validate_password(self, value: str) -> str:
        validate_password(value)
        return value
    
    def create(self, validated_data: Dict[str, Any]) -> User:
        # Generate username from email
        email = validated_data['email']
        username = email.split('@')[0]
        counter = 1
        original_username = username
        
        while User.objects.filter(username=username).exists():
            username = f"{original_username}{counter}"
            counter += 1
        
        user = User.objects.create_user(
            username=username,
            **validated_data
        )
        return user

class CategorySerializer(serializers.ModelSerializer):
    """Serializer for Category model"""
    
    class Meta:
        model = Category
        fields = ['id', 'name', 'type', 'color', 'icon', 'user', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']
        extra_kwargs: Dict[str, Any] = {}
    
    def create(self, validated_data):
        """Set the user from the request context when creating a new category"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['user'] = request.user
        return super().create(validated_data)
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        # Check for duplicate category name per user and type
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            user = request.user
            name = attrs.get('name')
            category_type = attrs.get('type')
            
            # For updates, exclude current instance
            queryset = Category.objects.filter(user=user, name=name, type=category_type)
            if self.instance and hasattr(self.instance, 'id'):
                try:
                    queryset = queryset.exclude(id=self.instance.id)  # type: ignore
                except AttributeError:
                    pass
            
            if queryset.exists():
                raise serializers.ValidationError(  # type: ignore
                    f"Category '{name}' already exists for {category_type} type"
                )
        
        return attrs

class TransactionSerializer(serializers.ModelSerializer):
    """Serializer for Transaction model"""
    category_name = serializers.CharField(source='category.name', read_only=True)
    category_color = serializers.CharField(source='category.color', read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'title', 'amount', 'type', 'category', 'category_name', 'category_color',
            'description', 'date', 'user', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']
        extra_kwargs: Dict[str, Any] = {}
    
    def create(self, validated_data):
        """Set the user from the request context when creating a new transaction"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['user'] = request.user
        return super().create(validated_data)
    
    def validate_category(self, value: Union[Category, None]) -> Union[Category, None]:
        """Ensure category belongs to the user and matches transaction type"""
        if value:
            request = self.context.get('request')
            if request and hasattr(request, 'user'):
                if value.user != request.user:
                    raise serializers.ValidationError("Category does not belong to user")  # type: ignore
        return value
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that category type matches transaction type"""
        category = attrs.get('category')
        transaction_type = attrs.get('type')
        
        if category and category.type != transaction_type:
            raise serializers.ValidationError(  # type: ignore
                f"Category type '{category.type}' doesn't match transaction type '{transaction_type}'"
            )
        
        return attrs

class BudgetSerializer(serializers.ModelSerializer):
    """Serializer for Budget model"""
    remaining_budget = serializers.ReadOnlyField()
    budget_percentage_used = serializers.ReadOnlyField()
    
    class Meta:
        model = Budget
        fields = [
            'id', 'month', 'year', 'total_budget', 'currency',
            'category_budgets', 'total_spent', 'remaining_budget',
            'budget_percentage_used', 'alert_sent', 'user', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'total_spent', 'alert_sent', 'user', 'created_at', 'updated_at']
        extra_kwargs: Dict[str, Any] = {}
    
    def create(self, validated_data):
        """Set the user from the request context when creating a new budget"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['user'] = request.user
        return super().create(validated_data)

class BudgetAlertSerializer(serializers.ModelSerializer):
    """Serializer for Budget Alert model"""
    
    class Meta:
        model = BudgetAlert
        fields = [
            'id', 'budget', 'alert_type', 'message', 'threshold_percentage',
            'is_read', 'user', 'created_at'
        ]
        read_only_fields = ['id', 'user', 'created_at']
        extra_kwargs: Dict[str, Any] = {}
    
    def create(self, validated_data):
        """Set the user from the request context when creating a new budget alert"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['user'] = request.user
        return super().create(validated_data)

class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for Notification model"""
    
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'type', 'read', 'user', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']
        extra_kwargs: Dict[str, Any] = {}
    
    def create(self, validated_data):
        """Set the user from the request context when creating a new notification"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['user'] = request.user
        return super().create(validated_data)

class MonthlyReportSerializer(serializers.ModelSerializer):
    """Serializer for Monthly Report model"""
    savings_rate = serializers.ReadOnlyField()
    
    class Meta:
        model = MonthlyReport
        fields = [
            'id', 'month', 'year', 'total_income', 'total_expenses', 'net_income',
            'income_by_category', 'expenses_by_category', 'compared_to_previous_month',
            'budget_analysis', 'savings_rate', 'user', 'generated_at', 'is_final'
        ]
        read_only_fields = ['id', 'user', 'generated_at']
        extra_kwargs: Dict[str, Any] = {}
    
    def create(self, validated_data):
        """Set the user from the request context when creating a new monthly report"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['user'] = request.user
        return super().create(validated_data)