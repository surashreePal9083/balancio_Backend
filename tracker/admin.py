from django.contrib import admin
from .models import User, Transaction, Category, Notification

# Register our models so we can manage them through Django admin
# Think of this like giving the admin panel access to our data

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['username', 'email', 'first_name', 'last_name', 'date_joined']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    list_filter = ['date_joined', 'is_staff', 'is_active']

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'type', 'user', 'color', 'created_at']
    list_filter = ['type', 'created_at']
    search_fields = ['name', 'user__username']

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ['title', 'amount', 'type', 'user', 'category', 'date']
    list_filter = ['type', 'date', 'created_at']
    search_fields = ['title', 'user__username', 'description']
    date_hierarchy = 'date'

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['title', 'user', 'type', 'read', 'created_at']
    list_filter = ['type', 'read', 'created_at']
    search_fields = ['title', 'message', 'user__username']
