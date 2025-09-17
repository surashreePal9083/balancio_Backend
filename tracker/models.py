from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal

# User model - This is like a profile card for each person using our app
class User(AbstractUser):
    # Basic info about the user
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    
    # Profile information
    phone_number = models.CharField(max_length=20, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_picture = models.URLField(blank=True)
    bio = models.TextField(max_length=500, blank=True)
    
    # Budget settings - How much money they plan to spend each month
    monthly_budget_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    monthly_budget_currency = models.CharField(max_length=3, default='USD')
    
    # Alert settings - When to warn them about spending too much
    budget_warning_threshold = models.IntegerField(default=80, validators=[MinValueValidator(1), MaxValueValidator(100)])
    budget_critical_threshold = models.IntegerField(default=95, validators=[MinValueValidator(1), MaxValueValidator(100)])
    
    # Notification preferences - What kind of messages they want to receive
    email_notifications = models.BooleanField(default=True)
    budget_alerts = models.BooleanField(default=True)
    monthly_reports = models.BooleanField(default=True)
    
    # Social auth providers
    google_id = models.CharField(max_length=100, blank=True, null=True)
    github_id = models.CharField(max_length=100, blank=True, null=True)
    
    # User preferences
    preferred_currency = models.CharField(max_length=3, default='USD')
    date_format_preference = models.CharField(max_length=20, default='MM/dd/yyyy')
    timezone_preference = models.CharField(max_length=50, default='UTC')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

# Category model - Like different folders to organize money transactions
class Category(models.Model):
    CATEGORY_TYPES = [
        ('income', 'Money Coming In'),
        ('expense', 'Money Going Out'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='categories')
    name = models.CharField(max_length=100)  # Like "Food", "Salary", "Games"
    type = models.CharField(max_length=10, choices=CATEGORY_TYPES)
    color = models.CharField(max_length=7, default='#3B82F6')  # Color to make it pretty
    icon = models.CharField(max_length=50, default='category')  # Little picture
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name_plural = "Categories"
        unique_together = ['user', 'name', 'type']
    
    def __str__(self):
        return f"{self.name} ({self.type})"

# Transaction model - Each time money comes in or goes out
class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('income', 'Money Coming In'),
        ('expense', 'Money Going Out'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    title = models.CharField(max_length=200)  # Like "Bought lunch" or "Got allowance"
    amount = models.DecimalField(max_digits=10, decimal_places=2)  # How much money
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField(blank=True)  # Extra details if needed
    date = models.DateTimeField()  # When it happened
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-date']  # Show newest first
    
    def __str__(self):
        return f"{self.title} - ${self.amount} ({self.type})"

# Notification model - Messages for the user
class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('info', 'Information'),
        ('success', 'Good News'),
        ('warning', 'Be Careful'),
        ('error', 'Problem'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=200)
    message = models.TextField()
    type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES, default='info')
    read = models.BooleanField(default=False)  # Has the user seen this message?
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']  # Show newest first
    
    def __str__(self):
        return f"{self.title} - {self.user.username}"

# Budget model - Monthly budget management
class Budget(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_budgets')
    month = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(12)])
    year = models.IntegerField(validators=[MinValueValidator(2020)])
    total_budget = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    
    # Budget breakdown by categories
    category_budgets = models.JSONField(default=dict)  # {category_id: amount}
    
    # Tracking
    total_spent = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    alert_sent = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['user', 'month', 'year']
        ordering = ['-year', '-month']
    
    def __str__(self):
        return f"{self.user.username} - {self.month}/{self.year} Budget"
    
    @property
    def remaining_budget(self):
        return self.total_budget - self.total_spent
    
    @property
    def budget_percentage_used(self):
        if self.total_budget > 0:
            return (self.total_spent / self.total_budget) * 100
        return 0
    
    def should_send_alert(self):
        percentage = self.budget_percentage_used
        return (
            percentage >= self.user.budget_warning_threshold and 
            not self.alert_sent
        )

# BudgetAlert model - Budget alerts and notifications
class BudgetAlert(models.Model):
    ALERT_TYPES = [
        ('warning', 'Warning'),
        ('critical', 'Critical'),
        ('exceeded', 'Budget Exceeded'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_budget_alerts')
    budget = models.ForeignKey(Budget, on_delete=models.CASCADE, related_name='alerts')
    alert_type = models.CharField(max_length=10, choices=ALERT_TYPES)
    message = models.TextField()
    threshold_percentage = models.DecimalField(max_digits=5, decimal_places=2)
    
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.alert_type.title()} Alert - {self.user.username}"

# MonthlyReport model - Generated monthly financial reports
class MonthlyReport(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_monthly_reports')
    month = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(12)])
    year = models.IntegerField(validators=[MinValueValidator(2020)])
    
    # Financial summary
    total_income = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_expenses = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    net_income = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Category breakdown
    income_by_category = models.JSONField(default=dict)
    expenses_by_category = models.JSONField(default=dict)
    
    # Trends and insights
    compared_to_previous_month = models.JSONField(default=dict)
    budget_analysis = models.JSONField(default=dict)
    
    # Report generation
    generated_at = models.DateTimeField(auto_now_add=True)
    is_final = models.BooleanField(default=False)  # True if month is complete
    
    class Meta:
        unique_together = ['user', 'month', 'year']
        ordering = ['-year', '-month']
    
    def __str__(self):
        return f"{self.user.username} - {self.month}/{self.year} Report"
    
    @property
    def savings_rate(self):
        if self.total_income > 0:
            return ((self.total_income - self.total_expenses) / self.total_income) * 100
        return 0
