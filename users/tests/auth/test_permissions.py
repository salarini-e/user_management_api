"""Testes de permissões e autorização."""
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User
from rest_framework import status

from ..base import BaseUserTestCase


class PermissionTestCase(BaseUserTestCase):
    """Testes específicos para permissões baseadas em grupos."""
    
    def setUp(self):
        super().setUp()
        
        # Cria usuários com diferentes permissões
        self.admin_user = self.create_admin_user()
        self.regular_user = self.create_regular_user()
        
        # Cria permissões específicas se necessário
        content_type = ContentType.objects.get_for_model(User)
        self.view_user_permission = Permission.objects.get_or_create(
            codename='view_user',
            name='Can view user',
            content_type=content_type,
        )[0]
    
    def test_admin_user_access(self):
        """Testa acesso de usuário administrador."""
        # Autentica como admin
        self.authenticate_user(self.admin_user)
        
        # Admin deve ter acesso ao próprio perfil
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se retornou dados do admin
        self.assertEqual(response.data['username'], 'admin')
    
    def test_regular_user_access(self):
        """Testa acesso de usuário comum."""
        # Autentica como usuário comum
        self.authenticate_user(self.regular_user)
        
        # Usuário comum deve ter acesso ao próprio perfil
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica se retornou dados do usuário comum
        self.assertEqual(response.data['username'], 'regular')
    
    def test_user_group_membership(self):
        """Testa se os usuários estão nos grupos corretos."""
        # Verifica grupo do admin
        self.assertTrue(self.admin_user.groups.filter(name='admin').exists())
        
        # Verifica grupo do usuário comum
        self.assertTrue(self.regular_user.groups.filter(name='users').exists())
        
        # Verifica que o usuário comum não está no grupo admin
        self.assertFalse(self.regular_user.groups.filter(name='admin').exists())
    
    def test_access_with_different_tokens(self):
        """Testa acesso com tokens de diferentes usuários."""
        # Autentica como admin
        self.authenticate_user(self.admin_user)
        
        # Limpa credenciais
        self.client.credentials()
        
        # Autentica com token do usuário comum
        self.authenticate_user(self.regular_user)
        
        # Cada usuário deve ver apenas seus próprios dados
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'regular')
