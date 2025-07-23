"""Testes para UserProfileSerializer."""
from ..base import BaseModelTestCase, TestDataMixin
from ...serializers import UserProfileSerializer


class UserProfileSerializerTest(BaseModelTestCase, TestDataMixin):
    """Testes para UserProfileSerializer."""
    
    def test_profile_serializer_valid_data(self):
        """Testa serialização com dados válidos."""
        valid_data = self.get_valid_profile_data()
        
        serializer = UserProfileSerializer(data=valid_data)
        self.assertTrue(serializer.is_valid())
        
        # Verifica se os dados estão corretos
        self.assertEqual(serializer.validated_data['full_name'], 'Complete Name')
        self.assertEqual(serializer.validated_data['phone'], '+5511999999999')
    
    def test_profile_serializer_partial_update(self):
        """Testa atualização parcial do perfil."""
        profile = self.user.profile
        
        partial_data = {
            'bio': 'Updated bio only'
        }
        
        serializer = UserProfileSerializer(
            profile, 
            data=partial_data, 
            partial=True
        )
        
        self.assertTrue(serializer.is_valid())
        updated_profile = serializer.save()
        
        self.assertEqual(updated_profile.bio, 'Updated bio only')
    
    def test_profile_serializer_read(self):
        """Testa leitura do perfil."""
        profile = self.user.profile
        profile.full_name = 'Test Read'
        profile.phone = '+5511123456789'
        profile.save()
        
        serializer = UserProfileSerializer(profile)
        data = serializer.data
        
        self.assertEqual(data['full_name'], 'Test Read')
        self.assertEqual(data['phone'], '+5511123456789')
        self.assertIn('timezone', data)
        self.assertIn('language', data)
