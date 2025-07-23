from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    # Autenticação
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('token/refresh/', views.TokenRefreshView.as_view(), name='token_refresh'),
    
    # Usuário
    path('user/', views.UserProfileView.as_view(), name='user_profile'),
    
    # Utilitários
    path('health/', views.health_check, name='health_check'),
]
