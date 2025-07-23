"""Testes de logout."""
from datetime import timedelta
from django.conf import settings
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from ..base import BaseUserTestCase


class LogoutTestCase(BaseUserTestCase):
    """Testes específicos para logout."""
    
    def test_logout_with_valid_token(self):
        """Testa logout com token válido."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        data = {'refresh': str(self.refresh_token)}
        response = self.post_json(self.logout_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.json())
        self.assertEqual(response.json()['message'], 'Logout realizado com sucesso')
        
        # Verifica se o cookie foi removido
        self.assertIn(settings.AUTH_COOKIE_NAME, response.cookies)
    
    def test_logout_without_auth(self):
        """Testa logout sem autenticação."""
        data = {'refresh': str(self.refresh_token)}
        response = self.post_json(self.logout_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_logout_without_refresh_token(self):
        """Testa logout sem refresh token."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.post_json(self.logout_url, {})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_logout_with_expired_refresh_token(self):
        """Testa logout com refresh token expirado."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        # Cria um token expirado
        expired_token = RefreshToken.for_user(self.user)
        expired_token.set_exp(lifetime=timedelta(seconds=-1))
        
        data = {'refresh': str(expired_token)}
        response = self.post_json(self.logout_url, data)
        
        # Logout deve funcionar mesmo com token expirado
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(settings.AUTH_COOKIE_NAME, response.cookies)
