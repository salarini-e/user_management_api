"""Testes para UserSerializer."""
from ..base import BaseModelTestCase, AssertionHelpers
from ...serializers import UserSerializer


class UserSerializerTest(BaseModelTestCase, AssertionHelpers):
    """Testes para o UserSerializer."""
    
    def setUp(self):
        super().setUp()
        # Atualiza perfil do usuário de teste
        profile = self.user.profile
        profile.full_name = 'Test User Complete'
        profile.phone = '+5511999999999'
        profile.bio = 'Test bio'
        profile.save()
    
    def test_user_serializer_read(self):
        """Testa a serialização de leitura do usuário."""
        serializer = UserSerializer(self.user)
        data = serializer.data
        
        # Verifica estrutura
        self.assert_user_data_structure(data)
        
        # Verifica valores específicos
        self.assertEqual(data['username'], 'testuser')
        self.assertEqual(data['email'], 'test@example.com')
        self.assertEqual(data['first_name'], 'Test')
        self.assertEqual(data['last_name'], 'User')
        self.assertTrue(data['is_active'])
        
        # Verifica perfil aninhado
        self.assert_profile_data_structure(data['profile'])
        self.assertEqual(data['profile']['full_name'], 'Test User Complete')
        self.assertEqual(data['profile']['phone'], '+5511999999999')
        self.assertEqual(data['profile']['bio'], 'Test bio')
    
    def test_user_serializer_update(self):
        """Testa atualização através do serializer."""
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'profile': {
                'bio': 'Updated bio',
                'phone': '+5511888888888'
            }
        }
        
        serializer = UserSerializer(
            self.user, 
            data=update_data, 
            partial=True
        )
        
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        
        # Verifica se os dados foram atualizados
        self.assertEqual(user.first_name, 'Updated')
        self.assertEqual(user.last_name, 'Name')
        
        # Recarrega perfil
        user.profile.refresh_from_db()
        self.assertEqual(user.profile.bio, 'Updated bio')
        self.assertEqual(user.profile.phone, '+5511888888888')
    
    def test_user_serializer_groups(self):
        """Testa se os grupos são serializados corretamente."""
        # Adiciona usuário a um grupo
        self.user.groups.add(self.admin_group)
        
        serializer = UserSerializer(self.user)
        data = serializer.data
        
        # Verifica se groups é uma lista
        self.assertIsInstance(data['groups'], list)
        
        # Verifica se contém o grupo admin
        group_names = [group['name'] for group in data['groups']]
        self.assertIn('admin', group_names)
    
    def test_user_serializer_no_password_exposure(self):
        """Testa se a senha não é exposta."""
        serializer = UserSerializer(self.user)
        data = serializer.data
        
        # Verifica que não há campos sensíveis
        self.assert_no_sensitive_data(data)
