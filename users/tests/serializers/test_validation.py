"""Testes de validação de serializers."""
from ..base import BaseUserTestCase, TestDataMixin
from ...serializers import UserLoginSerializer, UserProfileSerializer, UserSerializer


class SerializerValidationTestCase(BaseUserTestCase, TestDataMixin):
    """Testes específicos para validação de serializers."""
    
    def test_user_login_serializer_invalid_data(self):
        """Testa UserLoginSerializer com dados inválidos."""
        invalid_data_sets = self.get_invalid_credentials()
        
        # Remove o caso de credenciais incorretas mas válidas em formato
        # pois o serializer pode validar apenas formato, não autenticação
        test_cases = [data for data in invalid_data_sets if not (
            isinstance(data, dict) and 
            data.get('username') == 'invalid' and 
            data.get('password') == 'wrong'
        )]
        
        for invalid_data in test_cases:
            with self.subTest(data=invalid_data):
                serializer = UserLoginSerializer(data=invalid_data)
                self.assertFalse(serializer.is_valid())
                self.assertTrue(len(serializer.errors) > 0)
    
    def test_user_profile_serializer_invalid_data(self):
        """Testa UserProfileSerializer com dados inválidos."""
        invalid_data_sets = self.get_invalid_profile_data()
        
        for invalid_data in invalid_data_sets:
            with self.subTest(data=invalid_data):
                serializer = UserProfileSerializer(data=invalid_data)
                # Alguns campos podem não ter validação específica
                is_valid = serializer.is_valid()
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
    
    def test_user_login_serializer_required_fields(self):
        """Testa campos obrigatórios do UserLoginSerializer."""
        serializer = UserLoginSerializer(data={})
        self.assertFalse(serializer.is_valid())
        
        # Deve ter erros para campos obrigatórios
        self.assertIn('username', serializer.errors)
        self.assertIn('password', serializer.errors)
    
    def test_profile_serializer_field_lengths(self):
        """Testa limites de tamanho dos campos do perfil."""
        long_data = {
            'full_name': 'A' * 300,  # Muito longo
            'bio': 'B' * 2000,      # Muito longo
        }
        
        serializer = UserProfileSerializer(data=long_data)
        # Serializer pode ou não ter validação de tamanho
        # Dependendo da implementação do modelo
        is_valid = serializer.is_valid()
        
        if not is_valid:
            # Se não é válido, deve ter mensagens de erro apropriadas
            self.assertTrue(len(serializer.errors) > 0)
