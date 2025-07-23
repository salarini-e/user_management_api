"""Testes para o modelo UserProfile."""
from django.test import TestCase
from django.contrib.auth.models import User

from ..base import BaseModelTestCase
from ...models import UserProfile


class UserProfileModelTest(BaseModelTestCase):
    """Testes para o modelo UserProfile."""
    
    def test_user_profile_creation(self):
        """Testa se o perfil do usuário é criado automaticamente."""
        profile = self.user.profile
        self.assertEqual(profile.user, self.user)
        self.assertIsNotNone(profile)
    
    def test_user_profile_str(self):
        """Testa a representação string do perfil."""
        profile = self.user.profile
        self.assertEqual(str(profile), f"Perfil de {self.user.username}")
    
    def test_profile_fields(self):
        """Testa se os campos do perfil funcionam corretamente."""
        profile = self.user.profile
        
        # Atualiza campos
        profile.full_name = 'Nome Completo Test'
        profile.phone = '+5511999999999'
        profile.bio = 'Biografia de teste'
        profile.save()
        
        # Recarrega do banco
        profile.refresh_from_db()
        
        # Verifica se foram salvos
        self.assertEqual(profile.full_name, 'Nome Completo Test')
        self.assertEqual(profile.phone, '+5511999999999')
        self.assertEqual(profile.bio, 'Biografia de teste')
    
    def test_profile_auto_creation_on_user_save(self):
        """Testa se o perfil é criado automaticamente quando usuário é salvo."""
        new_user = User.objects.create_user(
            username='newuser',
            email='newuser@example.com',
            password='newpass123'
        )
        
        # Deve ter um perfil associado
        self.assertTrue(hasattr(new_user, 'profile'))
        self.assertIsInstance(new_user.profile, UserProfile)
        self.assertEqual(new_user.profile.user, new_user)
    
    def test_profile_timestamps(self):
        """Testa se os timestamps são criados corretamente."""
        profile = self.user.profile
        
        # Verifica se tem timestamps
        self.assertIsNotNone(profile.created_at)
        self.assertIsNotNone(profile.updated_at)
        
        # Atualiza perfil
        original_updated = profile.updated_at
        profile.bio = 'Bio atualizada'
        profile.save()
        
        # Verifica se updated_at foi alterado
        profile.refresh_from_db()
        self.assertGreater(profile.updated_at, original_updated)
