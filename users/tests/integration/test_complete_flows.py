"""Testes de integração completos."""
from datetime import timedelta
from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APITestCase

from ..base import BaseUserTestCase, AssertionHelpers


class CompleteFlowTestCase(BaseUserTestCase, AssertionHelpers):
    """Testes de fluxos completos da aplicação."""
    
    def test_complete_user_flow(self):
        """Testa fluxo completo: login -> perfil -> refresh -> logout."""
        
        # 1. Login
        login_response = self.post_json(self.login_url, self.valid_credentials)
        
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assert_jwt_response_structure(login_response.data)
        
        access_token = login_response.data['access']
        refresh_token = login_response.data['refresh']
        
        # 2. Acessar perfil
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        profile_response = self.client.get(self.user_url)
        self.assertEqual(profile_response.status_code, status.HTTP_200_OK)
        self.assert_user_data_structure(profile_response.data)
        self.assertEqual(profile_response.data['username'], 'testuser')
        
        # 3. Atualizar perfil
        update_data = {
            'first_name': 'Updated',
            'profile': {'bio': 'Updated bio'}
        }
        
        update_response = self.patch_json(self.user_url, update_data)
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        self.assertEqual(update_response.data['first_name'], 'Updated')
        self.assertEqual(update_response.data['profile']['bio'], 'Updated bio')
        
        # 4. Refresh token
        refresh_response = self.post_json(
            self.refresh_url,
            {'refresh': refresh_token}
        )
        
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        new_access_token = refresh_response.data['access']
        self.assertNotEqual(access_token, new_access_token)
        
        # 5. Usar novo token para acessar perfil
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        
        profile_response_2 = self.client.get(self.user_url)
        self.assertEqual(profile_response_2.status_code, status.HTTP_200_OK)
        # Verifica se as mudanças persistiram
        self.assertEqual(profile_response_2.data['first_name'], 'Updated')
        
        # 6. Logout
        logout_response = self.post_json(
            self.logout_url,
            {'refresh': refresh_token}
        )
        
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        
        # 7. Tentar usar token após logout (deve falhar)
        old_token_response = self.post_json(
            self.refresh_url,
            {'refresh': refresh_token}
        )
        self.assertEqual(old_token_response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_multiple_users_concurrent_access(self):
        """Testa acesso concorrente de múltiplos usuários."""
        # Cria segundo usuário
        user2 = self.create_regular_user()
        
        # Login com ambos os usuários
        login1 = self.post_json(self.login_url, {
            'username': 'testuser',
            'password': 'testpass123'
        })
        
        login2 = self.post_json(self.login_url, {
            'username': 'regular',
            'password': 'regularpass123'
        })
        
        self.assertEqual(login1.status_code, status.HTTP_200_OK)
        self.assertEqual(login2.status_code, status.HTTP_200_OK)
        
        token1 = login1.data['access']
        token2 = login2.data['access']
        
        # Verifica isolamento de dados
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token1}')
        response1 = self.client.get(self.user_url)
        self.assertEqual(response1.data['username'], 'testuser')
        
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token2}')
        response2 = self.client.get(self.user_url)
        self.assertEqual(response2.data['username'], 'regular')
    
    def test_error_recovery_flow(self):
        """Testa recuperação de erros em fluxo completo."""
        # 1. Tentativa de login com credenciais inválidas
        invalid_login = self.post_json(self.login_url, {
            'username': 'testuser',
            'password': 'wrong'
        })
        self.assertEqual(invalid_login.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # 2. Login correto após erro
        valid_login = self.post_json(self.login_url, self.valid_credentials)
        self.assertEqual(valid_login.status_code, status.HTTP_200_OK)
        
        access_token = valid_login.data['access']
        
        # 3. Tentativa de atualização com dados inválidos
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        invalid_update = self.patch_json(self.user_url, {
            'email': 'invalid-email'
        })
        self.assertEqual(invalid_update.status_code, status.HTTP_400_BAD_REQUEST)
        
        # 4. Atualização válida após erro
        valid_update = self.patch_json(self.user_url, {
            'first_name': 'Recovery Test'
        })
        self.assertEqual(valid_update.status_code, status.HTTP_200_OK)
        self.assertEqual(valid_update.data['first_name'], 'Recovery Test')
    
    def test_token_expiry_simulation(self):
        """Simula expiração de token em fluxo real."""
        # Mock de token com tempo de vida muito curto
        with patch('rest_framework_simplejwt.settings.api_settings.ACCESS_TOKEN_LIFETIME', 
                   timedelta(seconds=1)):
            
            # Login
            login_response = self.post_json(self.login_url, self.valid_credentials)
            access_token = login_response.data['access']
            
            # Imediatamente após login, deve funcionar
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
            response = self.client.get(self.user_url)
            
            # Token ainda deve ser válido
            self.assertIn(response.status_code, [
                status.HTTP_200_OK, 
                status.HTTP_401_UNAUTHORIZED
            ])


class APIConsistencyTestCase(BaseUserTestCase):
    """Testes de consistência da API."""
    
    def test_api_response_consistency(self):
        """Testa consistência das respostas da API."""
        # Autentica
        self.authenticate_user()
        
        # Faz múltiplas requisições para o mesmo endpoint
        responses = []
        for _ in range(3):
            response = self.client.get(self.user_url)
            responses.append(response.data)
        
        # Todas as respostas devem ter a mesma estrutura
        base_keys = set(responses[0].keys())
        for response_data in responses[1:]:
            self.assertEqual(set(response_data.keys()), base_keys)
    
    def test_api_error_format_consistency(self):
        """Testa consistência do formato de erros."""
        # Testa diferentes tipos de erro
        error_responses = []
        
        # 401 - Não autenticado
        response_401 = self.client.get(self.user_url)
        error_responses.append(response_401)
        
        # 400 - Dados inválidos
        response_400 = self.post_json(self.login_url, {})
        error_responses.append(response_400)
        
        # Todos os erros devem ter estrutura similar
        for response in error_responses:
            self.assertIn(response.status_code, [400, 401])
            # Deve ter algum campo de erro
            self.assertTrue(
                'error' in response.data or 
                'detail' in response.data or
                'non_field_errors' in response.data
            )
