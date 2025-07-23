"""Testes para endpoint de health check."""
from rest_framework import status

from ..base import BaseUserTestCase


class HealthCheckTestCase(BaseUserTestCase):
    """Testes para o endpoint de health check."""
    
    def test_health_check_response(self):
        """Testa o endpoint de health check."""
        response = self.client.get(self.health_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verifica estrutura da resposta
        self.assertIn('status', response.data)
        self.assertIn('timestamp', response.data)
        self.assertIn('version', response.data)
        
        # Verifica valores
        self.assertEqual(response.data['status'], 'healthy')
        self.assertIsNotNone(response.data['timestamp'])
        self.assertIsNotNone(response.data['version'])
    
    def test_health_check_no_auth_required(self):
        """Testa que health check não requer autenticação."""
        # Não autentica
        response = self.client.get(self.health_url)
        
        # Deve funcionar sem autenticação
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_health_check_method_not_allowed(self):
        """Testa métodos não permitidos no health check."""
        # Testa POST (não deveria ser permitido)
        response = self.client.post(self.health_url)
        
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def test_health_check_response_format(self):
        """Testa o formato da resposta do health check."""
        response = self.client.get(self.health_url)
        
        data = response.data
        
        # Verifica tipos dos campos
        self.assertIsInstance(data['status'], str)
        self.assertIsInstance(data['timestamp'], str)
        self.assertIsInstance(data['version'], str)
        
        # Verifica se timestamp está em formato ISO
        self.assertRegex(
            data['timestamp'], 
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        )
