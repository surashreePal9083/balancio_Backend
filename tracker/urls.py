from django.urls import path
from . import views

# API endpoints matching the frontend configuration exactly
# Based on the API_CONFIG.ENDPOINTS structure provided

urlpatterns = [
    # =============================================================================
    # AUTH ENDPOINTS - /api/auth/
    # =============================================================================
    path('api/auth/login/', views.auth_login, name='auth_login'),
    path('api/auth/signup/', views.auth_signup, name='auth_signup'),
    path('api/auth/refresh/', views.auth_refresh, name='auth_refresh'),
    path('api/auth/verify/', views.auth_verify, name='auth_verify'),
    path('api/auth/logout/', views.auth_logout, name='auth_logout'),
    
    # =============================================================================
    # USERS ENDPOINTS - /api/users/
    # =============================================================================
    path('api/users/profile/', views.users_profile, name='users_profile'),
    path('api/users/change-password/', views.users_change_password, name='users_change_password'),
    path('api/users/settings/', views.users_settings, name='users_settings'),
    path('api/users/activity/', views.users_activity, name='users_activity'),
    path('api/users/avatar/', views.users_avatar, name='users_avatar'),
    path('api/users/avatar/delete/', views.users_avatar_delete, name='users_avatar_delete'),
    
    # Dashboard statistics
    path('api/dashboard/statistics/', views.dashboard_statistics, name='dashboard_statistics'),
    
    # Additional user budget endpoints that frontend expects
    path('api/users/budget/', views.budget_list, name='users_budget'),
    path('api/users/budget/overview/', views.budget_overview, name='users_budget_overview'),
    path('api/users/budget/alerts/', views.budget_alerts, name='users_budget_alerts'),
    
    # =============================================================================
    # TRANSACTIONS ENDPOINTS - /api/transactions/
    # =============================================================================
    path('api/transactions/', views.transactions_list, name='transactions_list'),
    path('api/transactions/<int:transaction_id>/', views.transaction_detail, name='transaction_detail'),
    path('api/transactions/export/', views.transactions_export, name='transactions_export'),
    path('api/transactions/suggestions/', views.transaction_suggestions, name='transaction_suggestions'),
    
    # =============================================================================
    # CATEGORIES ENDPOINTS - /api/categories/
    # =============================================================================
    path('api/categories/', views.categories_list, name='categories_list'),
    path('api/categories/<int:category_id>/', views.category_detail, name='category_detail'),
    
    # =============================================================================
    # REPORTS ENDPOINTS - /api/reports/
    # =============================================================================
    path('api/reports/monthly/', views.reports_monthly, name='reports_monthly'),
    path('api/reports/monthly/<int:year>/<int:month>/download/', views.reports_download, name='reports_download'),
    
    # =============================================================================
    # BUDGET ENDPOINTS - /api/budget/
    # =============================================================================
    path('api/budget/', views.budget_list, name='budget_list'),
    path('api/budget/alerts/', views.budget_alerts, name='budget_alerts'),
]