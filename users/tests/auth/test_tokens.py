"""Testes de tokens JWT."""
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from ..base import BaseUserTestCase


class TokenRefreshTestCase(BaseUserTestCase):
    """Testes para refresh de tokens."""
    
    def test_token_refresh_valid(self):
        """Testa refresh de token com token válido."""
        data = {'refresh': str(self.refresh_token)}
        
        response = self.post_json(self.refresh_url, data)
        
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
        
        response = self.post_json(self.refresh_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_token_refresh_missing(self):
        """Testa refresh sem token."""
        response = self.post_json(self.refresh_url, {})
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_token_refresh_expired(self):
        """Testa refresh com token expirado."""
        # Cria um token que já está expirado
        expired_token = RefreshToken.for_user(self.user)
        expired_token.set_exp(lifetime=timedelta(seconds=-1))
        
        data = {'refresh': str(expired_token)}
        
        response = self.post_json(self.refresh_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TokenExpiredTestCase(BaseUserTestCase):
    """Testes para cenários com tokens expirados."""
    
    def test_logout_with_expired_refresh_token(self):
        """Testa logout com refresh token expirado."""
        self.authenticate_user()
        
        # Cria um token que já está expirado
        expired_token = RefreshToken.for_user(self.user)
        expired_token.set_exp(from_time=timezone.now() - timedelta(days=1))
        
        response = self.post_json(
            self.logout_url,
            {'refresh': str(expired_token)}
        )
        
        # O logout deve funcionar mesmo com token expirado
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_refresh_with_expired_token(self):
        """Testa refresh com token expirado manualmente."""
        # Token expirado manualmente criado
        expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTYwMDAwMDAwMCwiaWF0IjoxNjAwMDAwMDAwLCJqdGkiOiJleHBpcmVkdG9rZW4iLCJ1c2VyX2lkIjoxfQ.invalid"
        
        response = self.post_json(
            self.refresh_url,
            {'refresh': expired_token}
        )
        
        # Deve retornar erro por token inválido
        self.assertIn(response.status_code, [
            status.HTTP_401_UNAUTHORIZED, 
            status.HTTP_400_BAD_REQUEST
        ])
