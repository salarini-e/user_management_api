"""
Classes base e utilitários para testes.
"""
import json
from datetime import timedelta

from django.test import TestCase
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.conf import settings

from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from ..models import UserProfile, AuditLog


class BaseUserTestCase(APITestCase):
    """Classe base para testes que precisam de usuários."""
    
    def setUp(self):
        """Configuração comum para testes com usuários."""
        self.client = APIClient()
        
        # URLs comuns
        self.login_url = reverse('users:login')
        self.refresh_url = reverse('users:token_refresh')
        self.user_url = reverse('users:user_profile')
        self.logout_url = reverse('users:logout')
        self.health_url = reverse('users:health_check')
        
        # Criar usuário padrão
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Criar grupos de teste
        self.admin_group = Group.objects.create(name='admin')
        self.user_group = Group.objects.create(name='users')
        
        # Credenciais padrão
        self.valid_credentials = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        
        # Tokens padrão
        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = self.refresh_token.access_token
    
    def create_admin_user(self):
        """Cria um usuário administrador."""
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            first_name='Admin',
            last_name='User',
            is_staff=True
        )
        admin_user.groups.add(self.admin_group)
        return admin_user
    
    def create_regular_user(self):
        """Cria um usuário comum."""
        regular_user = User.objects.create_user(
            username='regular',
            email='regular@example.com',
            password='regularpass123',
            first_name='Regular',
            last_name='User'
        )
        regular_user.groups.add(self.user_group)
        return regular_user
    
    def authenticate_user(self, user=None):
        """Autentica um usuário e retorna os tokens."""
        if user is None:
            user = self.user
        
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        return str(access), str(refresh)
    
    def post_json(self, url, data):
        """Helper para fazer POST com JSON."""
        return self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )
    
    def patch_json(self, url, data):
        """Helper para fazer PATCH com JSON."""
        return self.client.patch(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )


class BaseModelTestCase(TestCase):
    """Classe base para testes de modelos."""
    
    def setUp(self):
        """Configuração comum para testes de modelos."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Criar grupo de teste
        self.admin_group = Group.objects.create(name='admin')
        self.user_group = Group.objects.create(name='users')


class TestDataMixin:
    """Mixin com dados de teste comuns."""
    
    @classmethod
    def get_valid_user_data(cls):
        """Retorna dados válidos para criação de usuário."""
        return {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpass123',
            'first_name': 'New',
            'last_name': 'User'
        }
    
    @classmethod
    def get_valid_profile_data(cls):
        """Retorna dados válidos para perfil."""
        return {
            'full_name': 'Complete Name',
            'phone': '+5511999999999',
            'bio': 'Test bio for user profile',
            'date_of_birth': '1990-01-01'
        }
    
    @classmethod
    def get_invalid_credentials(cls):
        """Retorna credenciais inválidas para testes."""
        return [
            {},  # Vazio
            {'username': ''},  # Username vazio
            {'password': ''},  # Password vazio
            {'username': 'test'},  # Sem password
            {'password': 'test'},  # Sem username
            {'username': '', 'password': ''},  # Ambos vazios
            {'username': 'invalid', 'password': 'wrong'},  # Credenciais incorretas
        ]
    
    @classmethod
    def get_invalid_profile_data(cls):
        """Retorna dados inválidos para perfil."""
        return [
            {'phone': 'invalid-phone'},  # Telefone inválido
            {'date_of_birth': 'invalid-date'},  # Data inválida
            {'full_name': 'A' * 201},  # Nome muito longo
            {'bio': 'B' * 1001},  # Bio muito longa
        ]


class AssertionHelpers:
    """Helper methods para assertions comuns."""
    
    def assert_user_data_structure(self, data):
        """Verifica se os dados do usuário têm a estrutura esperada."""
        required_fields = [
            'id', 'username', 'email', 'first_name', 
            'last_name', 'is_active', 'groups', 'profile'
        ]
        
        for field in required_fields:
            self.assertIn(field, data, f"Campo '{field}' não encontrado nos dados do usuário")
        
        # Verifica se não há campos sensíveis
        self.assertNotIn('password', data, "Senha não deve estar nos dados retornados")
    
    def assert_profile_data_structure(self, profile_data):
        """Verifica se os dados do perfil têm a estrutura esperada."""
        expected_fields = [
            'full_name', 'cpf', 'phone', 'date_of_birth', 'bio',
            'address', 'city', 'state', 'zip_code', 'full_address',
            'timezone', 'language', 'is_verified'
        ]
        
        for field in expected_fields:
            self.assertIn(field, profile_data, f"Campo '{field}' não encontrado no perfil")
    
    def assert_jwt_response_structure(self, response_data):
        """Verifica se a resposta de JWT tem a estrutura esperada."""
        required_fields = ['access', 'refresh', 'user', 'expires_in']
        
        for field in required_fields:
            self.assertIn(field, response_data, f"Campo '{field}' não encontrado na resposta JWT")
        
        # Verifica se os tokens são strings não vazias
        self.assertTrue(len(response_data['access']) > 50, "Token de acesso muito curto")
        self.assertTrue(len(response_data['refresh']) > 50, "Token de refresh muito curto")
    
    def assert_cookie_security(self, response):
        """Verifica se o cookie de autenticação está configurado corretamente."""
        self.assertIn(settings.AUTH_COOKIE_NAME, response.cookies)
        cookie = response.cookies[settings.AUTH_COOKIE_NAME]
        
        # Verifica configurações de segurança
        self.assertTrue(cookie['httponly'], "Cookie deve ser HttpOnly")
        self.assertEqual(cookie['path'], settings.AUTH_COOKIE_PATH, "Path do cookie incorreto")
        # Em produção, também verificaria 'secure': True
    
    def assert_no_sensitive_data(self, data):
        """Verifica recursivamente se não há dados sensíveis."""
        sensitive_fields = ['password', 'secret', 'key', 'token']
        
        def check_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Verifica se a chave é sensível
                    for sensitive in sensitive_fields:
                        if sensitive.lower() in key.lower():
                            self.fail(f"Campo sensível encontrado: {current_path}")
                    
                    check_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
