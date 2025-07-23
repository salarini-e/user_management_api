"""Testes de login e autenticação."""
import json
from django.urls import reverse
from django.conf import settings
from rest_framework import status

from ..base import BaseUserTestCase, TestDataMixin, AssertionHelpers


class LoginTestCase(BaseUserTestCase, TestDataMixin, AssertionHelpers):
    """Testes específicos para login."""
    
    def setUp(self):
        super().setUp()
        # Adicionar usuário ao grupo admin para alguns testes
        self.user.groups.add(self.admin_group)
        
        # Dados de login inválidos
        self.invalid_credentials = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
    
    def test_login_with_valid_credentials(self):
        """Testa autenticação com credenciais válidas."""
        response = self.post_json(self.login_url, self.valid_credentials)
        
        # Verifica status code
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica estrutura da resposta
        self.assert_jwt_response_structure(response.data)
        
        # Verifica dados do usuário
        user_data = response.data['user']
        self.assert_user_data_structure(user_data)
        self.assertEqual(user_data['username'], 'testuser')
        self.assertEqual(user_data['email'], 'test@example.com')
        
        # Verifica se o grupo admin está presente
        group_names = [group['name'] for group in user_data['groups']]
        self.assertIn('admin', group_names)
        
        # Verifica se o cookie foi setado
        self.assert_cookie_security(response)
    
    def test_login_with_email(self):
        """Testa autenticação usando email em vez de username."""
        email_credentials = {
            'username': 'test@example.com',  # Usando email no campo username
            'password': 'testpass123'
        }
        
        response = self.post_json(self.login_url, email_credentials)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertEqual(response.data['user']['username'], 'testuser')
    
    def test_login_with_invalid_credentials(self):
        """Testa autenticação com credenciais inválidas."""
        response = self.post_json(self.login_url, self.invalid_credentials)
        
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
        
        response = self.post_json(self.login_url, self.valid_credentials)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Conta desativada')
    
    def test_login_with_invalid_data(self):
        """Testa login com dados inválidos/faltando."""
        invalid_data_sets = self.get_invalid_credentials()
        
        for invalid_data in invalid_data_sets[:3]:  # Testa apenas alguns casos
            with self.subTest(data=invalid_data):
                response = self.post_json(self.login_url, invalid_data)
                
                self.assertIn(response.status_code, [
                    status.HTTP_400_BAD_REQUEST,
                    status.HTTP_401_UNAUTHORIZED
                ])
                
                if response.status_code == status.HTTP_400_BAD_REQUEST:
                    self.assertIn('error', response.data)
                    self.assertIn('details', response.data)
