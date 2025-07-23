"""Testes para API de perfil do usuário."""
from rest_framework import status

from ..base import BaseUserTestCase, AssertionHelpers


class UserProfileAPITestCase(BaseUserTestCase, AssertionHelpers):
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
        """Testa acesso ao endpoint /api/user/ com token válido."""
        # Autentica com token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.get(self.user_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica estrutura da resposta
        self.assert_user_data_structure(response.data)
        
        # Verifica dados específicos
        self.assertEqual(response.data['username'], 'testuser')
        self.assertEqual(response.data['email'], 'test@example.com')
        
        # Verifica dados do perfil
        profile_data = response.data['profile']
        self.assert_profile_data_structure(profile_data)
        self.assertEqual(profile_data['full_name'], 'Test User Full')
        self.assertEqual(profile_data['phone'], '+5511999999999')
        self.assertEqual(profile_data['bio'], 'Test bio')
    
    def test_get_user_profile_without_token(self):
        """Testa acesso sem token."""
        response = self.client.get(self.user_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_get_user_profile_with_invalid_token(self):
        """Testa token inválido."""
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
        
        response = self.patch_json(self.user_url, update_data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se os dados foram atualizados na resposta
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')
        self.assertEqual(response.data['profile']['bio'], 'Updated bio')
        self.assertEqual(response.data['profile']['phone'], '+5511888888888')
        
        # Verifica se foi persistido no banco
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')
        
        profile = self.user.profile
        profile.refresh_from_db()
        self.assertEqual(profile.bio, 'Updated bio')
        self.assertEqual(profile.phone, '+5511888888888')
    
    def test_update_profile_only(self):
        """Testa atualização apenas do perfil."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        update_data = {
            'profile': {
                'full_name': 'Only Profile Updated'
            }
        }
        
        response = self.patch_json(self.user_url, update_data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data['profile']['full_name'], 
            'Only Profile Updated'
        )
    
    def test_update_with_invalid_data(self):
        """Testa atualização com dados inválidos."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        invalid_data = {
            'email': 'invalid-email-format'
        }
        
        response = self.patch_json(self.user_url, invalid_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
