"""Testes de segurança de tokens."""
from rest_framework import status

from ..base import BaseUserTestCase, AssertionHelpers


class TokenSecurityTestCase(BaseUserTestCase, AssertionHelpers):
    """Testes específicos de segurança de tokens."""
    
    def test_password_not_in_response(self):
        """Testa se a senha não é retornada nas respostas."""
        # Autentica usuário
        self.authenticate_user()
        
        # Faz requisição para obter dados do usuário
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se a senha não está na resposta
        self.assert_no_sensitive_data(response.data)
    
    def test_jwt_token_blacklisting(self):
        """Testa se o blacklisting de tokens JWT funciona."""
        # Faz login
        response = self.post_json(self.login_url, self.valid_credentials)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        refresh_token = response.data['refresh']
        access_token = response.data['access']
        
        # Verifica se o token funciona
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Faz logout (deve blacklistar o token)
        response = self.post_json(
            self.logout_url,
            {'refresh': refresh_token}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Tenta usar o token refresh blacklistado
        response = self.post_json(
            self.refresh_url,
            {'refresh': refresh_token}
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_token_hijacking_protection(self):
        """Testa proteção contra sequestro de tokens."""
        # Cria dois usuários
        user1 = self.user
        user2 = self.create_regular_user()
        
        # Gera tokens para cada usuário
        access1, _ = self.authenticate_user(user1)
        
        # Limpa credenciais
        self.client.credentials()
        access2, _ = self.authenticate_user(user2)
        
        # Usa token do user1 (deve retornar dados do user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access1}')
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], user1.username)
        
        # Usa token do user2 (deve retornar dados do user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access2}')
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], user2.username)
    
    def test_malformed_token_handling(self):
        """Testa tratamento de tokens malformados."""
        malformed_tokens = [
            'invalid.token.here',
            'Bearer invalid',
            '...',
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid',
            '',
        ]
        
        for token in malformed_tokens:
            with self.subTest(token=token):
                self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
                response = self.client.get(self.user_url)
                
                # Deve retornar 401 para tokens inválidos
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_token_information_disclosure(self):
        """Testa se informações sensíveis não são vazadas em erros."""
        # Token inválido
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')
        response = self.client.get(self.user_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Verifica se a resposta não contém informações sensíveis
        response_text = str(response.data)
        sensitive_patterns = ['secret', 'key', 'password', 'private']
        
        for pattern in sensitive_patterns:
            self.assertNotIn(pattern.lower(), response_text.lower())
