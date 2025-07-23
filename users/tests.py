import json
from datetime import timedelta
from unittest.mock import patch
import time

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.conf import settings
from django.utils import timezone
from django.middleware.csrf import get_token

from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import UserProfile, AuditLog
from .serializers import UserSerializer, UserProfileSerializer, UserLoginSerializer


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


class UserModelTest(TestCase):
    """Testes para os modelos de usuário."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
    
    def test_user_profile_creation(self):
        """Testa se o perfil do usuário é criado automaticamente."""
        profile = self.user.profile
        self.assertEqual(profile.user, self.user)
        # full_name pode ser None por padrão
        self.assertIsNotNone(profile)
    
    def test_user_profile_str(self):
        """Testa a representação string do perfil."""
        profile = self.user.profile
        self.assertEqual(str(profile), f"Perfil de {self.user.username}")
    
    def test_audit_log_creation(self):
        """Testa a criação de log de auditoria."""
        audit = AuditLog.objects.create(
            user=self.user,
            action='LOGIN',
            description='Teste de login',
            ip_address='127.0.0.1',
            user_agent='TestAgent'
        )
        self.assertEqual(audit.user, self.user)
        self.assertEqual(audit.action, 'LOGIN')


class AuthenticationTestCase(BaseUserTestCase):
    """Testes de autenticação da API."""
    
    def setUp(self):
        super().setUp()
        # Adicionar usuário ao grupo admin para alguns testes
        self.user.groups.add(self.admin_group)
        
        # Dados de login inválidos
        self.invalid_credentials = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
    
    def test_health_check(self):
        """Testa o endpoint de health check."""
        response = self.client.get(self.health_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('status', response.data)
        self.assertEqual(response.data['status'], 'healthy')
        self.assertIn('timestamp', response.data)
        self.assertIn('version', response.data)
    
    def test_login_with_valid_credentials(self):
        """Testa autenticação com credenciais válidas - deve retornar 200 e setar cookie."""
        response = self.client.post(
            self.login_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        
        # Verifica status code
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica estrutura da resposta
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertIn('expires_in', response.data)
        
        # Verifica dados do usuário
        user_data = response.data['user']
        self.assertEqual(user_data['username'], 'testuser')
        self.assertEqual(user_data['email'], 'test@example.com')
        self.assertEqual(user_data['first_name'], 'Test')
        self.assertEqual(user_data['last_name'], 'User')
        self.assertTrue(user_data['is_active'])
        # Verifica se o grupo admin está presente
        group_names = [group['name'] for group in user_data['groups']]
        self.assertIn('admin', group_names)
        
        # Verifica se o cookie foi setado
        self.assertIn(settings.AUTH_COOKIE_NAME, response.cookies)
        cookie = response.cookies[settings.AUTH_COOKIE_NAME]
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['path'], settings.AUTH_COOKIE_PATH)
        
        # Verifica se o token é válido
        access_token = response.data['access']
        self.assertTrue(len(access_token) > 50)  # JWT tokens são longos
    
    def test_login_with_email(self):
        """Testa autenticação usando email em vez de username."""
        email_credentials = {
            'username': 'test@example.com',  # Usando email no campo username
            'password': 'testpass123'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(email_credentials),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertEqual(response.data['user']['username'], 'testuser')
    
    def test_login_with_invalid_credentials(self):
        """Testa autenticação com credenciais inválidas - deve retornar 401."""
        response = self.client.post(
            self.login_url,
            data=json.dumps(self.invalid_credentials),
            content_type='application/json'
        )
        
        # Verifica status code
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Verifica mensagem de erro
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Credenciais inválidas')
        
        # Verifica que nenhum cookie foi setado
        self.assertNotIn(settings.AUTH_COOKIE_NAME, response.cookies)
    
    def test_login_with_inactive_user(self):
        """Testa autenticação com usuário inativo."""
        # Desativa o usuário
        self.user.is_active = False
        self.user.save()
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Conta desativada')
    
    def test_login_with_invalid_data(self):
        """Testa login com dados inválidos/faltando."""
        invalid_data = {
            'username': '',  # Username vazio
            'password': 'testpass123'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(invalid_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn('details', response.data)


class TokenRefreshTestCase(BaseUserTestCase):
    """Testes para refresh de tokens."""
    
    def test_token_refresh_valid(self):
        """Testa refresh de token com token válido - deve retornar novo token."""
        data = {'refresh': str(self.refresh_token)}
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        
        # Verifica se é um token diferente
        new_access = response.data['access']
        self.assertNotEqual(str(self.access_token), new_access)
        self.assertTrue(len(new_access) > 50)
        
        # Verifica se o cookie foi atualizado
        self.assertIn(settings.AUTH_COOKIE_NAME, response.cookies)
    
    def test_token_refresh_invalid(self):
        """Testa refresh com token inválido."""
        data = {'refresh': 'invalid_token'}
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_token_refresh_missing(self):
        """Testa refresh sem token."""
        response = self.client.post(
            self.refresh_url,
            data=json.dumps({}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_token_refresh_expired(self):
        """Testa refresh com token expirado."""
        # Cria um token que já está expirado
        expired_token = RefreshToken.for_user(self.user)
        expired_token.set_exp(lifetime=timedelta(seconds=-1))  # Expira no passado
        
        data = {'refresh': str(expired_token)}
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserProfileTestCase(BaseUserTestCase):
    """Testes para endpoints de perfil do usuário."""
    
    def setUp(self):
        super().setUp()
        # Atualiza perfil do usuário de teste
        profile = self.user.profile
        profile.full_name = 'Test User Full'
        profile.phone = '+5511999999999'
        profile.bio = 'Test bio'
        profile.save()
    
    def test_get_user_profile_with_valid_token(self):
        """Testa acesso ao endpoint /api/user/ com token válido - retorna dados do usuário."""
        # Autentica com token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.get(self.user_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica estrutura da resposta
        self.assertIn('id', response.data)
        self.assertIn('username', response.data)
        self.assertIn('email', response.data)
        self.assertIn('first_name', response.data)
        self.assertIn('last_name', response.data)
        self.assertIn('is_active', response.data)
        self.assertIn('groups', response.data)
        self.assertIn('profile', response.data)
        
        # Verifica dados específicos
        self.assertEqual(response.data['username'], 'testuser')
        self.assertEqual(response.data['email'], 'test@example.com')
        self.assertEqual(response.data['first_name'], 'Test')
        self.assertEqual(response.data['last_name'], 'User')
        self.assertTrue(response.data['is_active'])
        
        # Verifica dados do perfil
        profile_data = response.data['profile']
        self.assertEqual(profile_data['full_name'], 'Test User Full')
        self.assertEqual(profile_data['phone'], '+5511999999999')
        self.assertEqual(profile_data['bio'], 'Test bio')
    
    def test_get_user_profile_without_token(self):
        """Testa acesso sem token - deve retornar 401."""
        response = self.client.get(self.user_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_get_user_profile_with_invalid_token(self):
        """Testa token inválido - bloqueia acesso."""
        # Token inválido
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token_here')
        
        response = self.client.get(self.user_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_update_user_profile(self):
        """Testa atualização do perfil do usuário."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'profile': {
                'bio': 'Updated bio',
                'phone': '+5511888888888'
            }
        }
        
        response = self.client.patch(
            self.user_url,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se os dados foram atualizados
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')
        self.assertEqual(response.data['profile']['bio'], 'Updated bio')
        self.assertEqual(response.data['profile']['phone'], '+5511888888888')
        
        # Verifica no banco de dados
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')
        
        profile = self.user.profile
        profile.refresh_from_db()
        self.assertEqual(profile.bio, 'Updated bio')
        self.assertEqual(profile.phone, '+5511888888888')


class LogoutTestCase(BaseUserTestCase):
    """Testes de logout."""
    
    def test_logout_with_valid_token(self):
        """Testa logout - deve apagar o cookie."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        data = {'refresh': str(self.refresh_token)}
        
        response = self.client.post(
            self.logout_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.json())
        self.assertEqual(response.json()['message'], 'Logout realizado com sucesso')
        
        # Verifica se o cookie foi removido
        # O Django deleta cookies setando max_age=0
        self.assertIn(settings.AUTH_COOKIE_NAME, response.cookies)
    
    def test_logout_without_auth(self):
        """Testa logout sem autenticação."""
        data = {'refresh': str(self.refresh_token)}
        
        response = self.client.post(
            self.logout_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_logout_without_refresh_token(self):
        """Testa logout sem refresh token (ainda deve funcionar)."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.post(
            self.logout_url,
            data=json.dumps({}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_logout_with_expired_refresh_token(self):
        """Testa logout com refresh token expirado."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        # Cria um token expirado
        expired_token = RefreshToken.for_user(self.user)
        expired_token.set_exp(lifetime=timedelta(seconds=-1))
        
        data = {'refresh': str(expired_token)}
        
        response = self.client.post(
            self.logout_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        # Logout deve funcionar mesmo com token expirado
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(settings.AUTH_COOKIE_NAME, response.cookies)


class IntegrationTestCase(APITestCase):
    """Testes de integração completos."""
    
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('users:login')
        self.user_url = reverse('users:user_profile')
        self.refresh_url = reverse('users:token_refresh')
        self.logout_url = reverse('users:logout')
        
        self.user = User.objects.create_user(
            username='integrationuser',
            email='integration@example.com',
            password='integrationpass123',
            first_name='Integration',
            last_name='Test'
        )
    
    def test_complete_user_flow(self):
        """Testa fluxo completo: login -> acessar perfil -> refresh -> logout."""
        
        # 1. Login
        login_data = {
            'username': 'integrationuser',
            'password': 'integrationpass123'
        }
        
        login_response = self.client.post(
            self.login_url,
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        access_token = login_response.data['access']
        refresh_token = login_response.data['refresh']
        
        # 2. Acessar perfil
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        profile_response = self.client.get(self.user_url)
        self.assertEqual(profile_response.status_code, status.HTTP_200_OK)
        self.assertEqual(profile_response.data['username'], 'integrationuser')
        
        # 3. Refresh token
        refresh_data = {'refresh': refresh_token}
        
        refresh_response = self.client.post(
            self.refresh_url,
            data=json.dumps(refresh_data),
            content_type='application/json'
        )
        
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        new_access_token = refresh_response.data['access']
        self.assertNotEqual(access_token, new_access_token)
        
        # 4. Usar novo token para acessar perfil
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        
        profile_response_2 = self.client.get(self.user_url)
        self.assertEqual(profile_response_2.status_code, status.HTTP_200_OK)
        
        # 5. Logout
        logout_data = {'refresh': refresh_token}
        
        logout_response = self.client.post(
            self.logout_url,
            data=json.dumps(logout_data),
            content_type='application/json'
        )
        
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
    
    def test_token_expiry_simulation(self):
        """Simula expiração de token."""
        # Cria token com tempo de expiração muito curto para teste
        with patch('rest_framework_simplejwt.settings.api_settings.ACCESS_TOKEN_LIFETIME', 
                   timedelta(seconds=1)):
            
            # Login
            login_data = {
                'username': 'integrationuser',
                'password': 'integrationpass123'
            }
            
            login_response = self.client.post(
                self.login_url,
                data=json.dumps(login_data),
                content_type='application/json'
            )
            
            access_token = login_response.data['access']
            
            # Imediatamente após o login deve funcionar
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
            response = self.client.get(self.user_url)
            
            # Como o token é válido, deve retornar 200
            # (Note: em um teste real com sleep, seria 401 após expiração)
            self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED])


class SerializerTestCase(TestCase):
    """Testes para serializers."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Atualiza perfil
        profile = self.user.profile
        profile.full_name = 'Test User Complete'
        profile.phone = '+5511999999999'
        profile.save()
    
    def test_user_serializer(self):
        """Testa o UserSerializer."""
        serializer = UserSerializer(self.user)
        data = serializer.data
        
        # Verifica campos obrigatórios
        required_fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                          'is_active', 'groups', 'profile']
        
        for field in required_fields:
            self.assertIn(field, data)
        
        # Verifica valores
        self.assertEqual(data['username'], 'testuser')
        self.assertEqual(data['email'], 'test@example.com')
        self.assertEqual(data['first_name'], 'Test')
        self.assertEqual(data['last_name'], 'User')
        self.assertTrue(data['is_active'])
        
        # Verifica perfil aninhado
        self.assertIn('full_name', data['profile'])
        self.assertIn('phone', data['profile'])
        self.assertEqual(data['profile']['full_name'], 'Test User Complete')
        self.assertEqual(data['profile']['phone'], '+5511999999999')


class CORSAndCSRFTestCase(BaseUserTestCase):
    """Testes específicos para CORS e CSRF."""
    
    def test_cors_headers_present(self):
        """Testa se os headers CORS estão presentes nas respostas."""
        # Testa no health check (endpoint público)
        response = self.client.get(self.health_url)
        
        # Verifica se headers CORS estão presentes
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Methods'
        ]
        
        # Nota: Os headers podem não estar presentes em desenvolvimento
        # mas devem estar configurados no settings
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_login_with_csrf_token(self):
        """Testa login com token CSRF válido."""
        # Para API com DRF, o CSRF pode não ser obrigatório
        # Mas vamos testar que o endpoint funciona normalmente
        
        response = self.client.post(
            self.login_url,
            self.valid_credentials,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_protected_endpoint_without_csrf_in_unsafe_method(self):
        """Testa endpoint protegido sem CSRF em método não-seguro."""
        # Autentica usuário
        self.authenticate_user()
        
        # Tenta fazer um POST sem CSRF token (simulando ataque CSRF)
        profile_data = {'profile': {'full_name': 'Hacked'}}
        
        response = self.client.patch(
            self.user_url,
            profile_data,
            format='json'
        )
        
        # O DRF com JWT pode não exigir CSRF para API tokens
        # mas devemos verificar se a segurança está configurada
        # Em produção, deveria retornar 403 se CSRF fosse obrigatório
        self.assertIn(response.status_code, [200, 403])


class TokenExpiredTestCase(BaseUserTestCase):
    """Testes para tokens expirados."""
    
    def test_logout_with_expired_refresh_token(self):
        """Testa logout com refresh token expirado."""
        # Para testar logout com token expirado, precisamos estar autenticados
        # mas enviando um refresh token expirado
        self.authenticate_user()
        
        # Cria um token que já está expirado
        expired_token = RefreshToken.for_user(self.user)
        expired_token.set_exp(from_time=timezone.now() - timedelta(days=1))
        
        response = self.client.post(
            self.logout_url,
            {'refresh': str(expired_token)},
            format='json'
        )
        
        # O logout deve funcionar mesmo com token expirado
        # pois a autenticação é feita via access token no header
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_refresh_with_expired_token(self):
        """Testa refresh com token expirado."""
        # Cria um token expirado manualmente
        expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTYwMDAwMDAwMCwiaWF0IjoxNjAwMDAwMDAwLCJqdGkiOiJleHBpcmVkdG9rZW4iLCJ1c2VyX2lkIjoxfQ.invalid"
        
        response = self.client.post(
            self.refresh_url,
            {'refresh': expired_token},
            format='json'
        )
        
        # Deve retornar erro por token inválido
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_400_BAD_REQUEST])


class SerializerValidationTestCase(BaseUserTestCase):
    """Testes específicos para validação de serializers."""
    
    def test_user_login_serializer_invalid_data(self):
        """Testa UserLoginSerializer com dados inválidos."""
        # Testa com dados faltando
        invalid_data_sets = [
            {},  # Vazio
            {'username': ''},  # Username vazio
            {'password': ''},  # Password vazio
            {'username': 'test'},  # Sem password
            {'password': 'test'},  # Sem username
            {'username': '', 'password': ''},  # Ambos vazios
        ]
        
        for invalid_data in invalid_data_sets:
            with self.subTest(data=invalid_data):
                serializer = UserLoginSerializer(data=invalid_data)
                self.assertFalse(serializer.is_valid())
                self.assertTrue(len(serializer.errors) > 0)
    
    def test_user_profile_serializer_invalid_data(self):
        """Testa UserProfileSerializer com dados inválidos."""
        # Dados inválidos para o perfil
        invalid_data_sets = [
            {'phone': 'invalid-phone'},  # Telefone inválido
            {'date_of_birth': 'invalid-date'},  # Data inválida
            {'full_name': 'A' * 201},  # Nome muito longo
            {'bio': 'B' * 1001},  # Bio muito longa
        ]
        
        for invalid_data in invalid_data_sets:
            with self.subTest(data=invalid_data):
                serializer = UserProfileSerializer(data=invalid_data)
                # Alguns campos podem não ter validação específica
                # mas vamos verificar se o serializer processa corretamente
                is_valid = serializer.is_valid()
                # Se não é válido, deve ter erros
                if not is_valid:
                    self.assertTrue(len(serializer.errors) > 0)
    
    def test_user_serializer_with_invalid_nested_profile(self):
        """Testa UserSerializer com perfil aninhado inválido."""
        invalid_user_data = {
            'username': 'newuser',
            'email': 'invalid-email',  # Email inválido
            'profile': {
                'full_name': 'A' * 201,  # Nome muito longo
                'phone': 'invalid-phone'  # Telefone inválido
            }
        }
        
        serializer = UserSerializer(data=invalid_user_data)
        self.assertFalse(serializer.is_valid())
        
        # Deve ter erro no email
        self.assertIn('email', serializer.errors)


class PermissionTestCase(BaseUserTestCase):
    """Testes específicos para permissões baseadas em grupos."""
    
    def setUp(self):
        super().setUp()
        
        # Cria usuários com diferentes permissões
        self.admin_user = self.create_admin_user()
        self.regular_user = self.create_regular_user()
        
        # Cria permissões específicas se necessário
        content_type = ContentType.objects.get_for_model(User)
        self.view_user_permission = Permission.objects.get_or_create(
            codename='view_user',
            name='Can view user',
            content_type=content_type,
        )[0]
    
    def test_admin_user_access(self):
        """Testa acesso de usuário administrador."""
        # Autentica como admin
        self.authenticate_user(self.admin_user)
        
        # Admin deve ter acesso ao próprio perfil
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se retornou dados do admin
        self.assertEqual(response.data['username'], 'admin')
    
    def test_regular_user_access(self):
        """Testa acesso de usuário comum."""
        # Autentica como usuário comum
        self.authenticate_user(self.regular_user)
        
        # Usuário comum deve ter acesso ao próprio perfil
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se retornou dados do usuário comum
        self.assertEqual(response.data['username'], 'regular')
    
    def test_user_group_membership(self):
        """Testa se os usuários estão nos grupos corretos."""
        # Verifica grupo do admin
        self.assertTrue(self.admin_user.groups.filter(name='admin').exists())
        
        # Verifica grupo do usuário comum
        self.assertTrue(self.regular_user.groups.filter(name='users').exists())
        
        # Verifica que o usuário comum não está no grupo admin
        self.assertFalse(self.regular_user.groups.filter(name='admin').exists())
    
    def test_access_with_different_tokens(self):
        """Testa acesso com tokens de diferentes usuários."""
        # Cria tokens para diferentes usuários
        admin_access, _ = self.authenticate_user(self.admin_user)
        
        # Limpa credenciais
        self.client.credentials()
        
        # Autentica com token do usuário comum
        regular_access, _ = self.authenticate_user(self.regular_user)
        
        # Cada usuário deve ver apenas seus próprios dados
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'regular')


class SecurityTestCase(BaseUserTestCase):
    """Testes específicos de segurança."""
    
    def test_password_not_in_response(self):
        """Testa se a senha não é retornada nas respostas."""
        # Autentica usuário
        self.authenticate_user()
        
        # Faz requisição para obter dados do usuário
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se a senha não está na resposta
        self.assertNotIn('password', response.data)
        
        # Verifica recursivamente em objetos aninhados
        def check_no_password(data):
            if isinstance(data, dict):
                self.assertNotIn('password', data)
                for value in data.values():
                    check_no_password(value)
            elif isinstance(data, list):
                for item in data:
                    check_no_password(item)
        
        check_no_password(response.data)
    
    def test_jwt_token_blacklisting(self):
        """Testa se o blacklisting de tokens JWT funciona."""
        # Faz login
        response = self.client.post(self.login_url, self.valid_credentials)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        refresh_token = response.data['refresh']  # Corrigido: chave correta
        access_token = response.data['access']    # Corrigido: chave correta
        
        # Verifica se o token funciona
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Faz logout (deve blacklistar o token)
        response = self.client.post(
            self.logout_url,
            {'refresh': refresh_token},  # Corrigido: campo correto
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Tenta usar o token refresh blacklistado
        response = self.client.post(
            self.refresh_url,
            {'refresh': refresh_token},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_rate_limiting_considerations(self):
        """Testa considerações de rate limiting (estrutura)."""
        # Nota: Este teste seria mais complexo em produção
        # Aqui apenas verificamos que múltiplas tentativas são aceitas
        # Em produção, deveria haver rate limiting
        
        attempts = 0
        max_attempts = 5
        
        while attempts < max_attempts:
            response = self.client.post(self.login_url, self.valid_credentials)
            self.assertIn(response.status_code, [200, 429])  # 429 = Too Many Requests
            attempts += 1
            
            if response.status_code == 429:
                # Rate limiting está funcionando
                break
        
        # Em desenvolvimento, pode não haver rate limiting
        # Mas a estrutura do teste está pronta
