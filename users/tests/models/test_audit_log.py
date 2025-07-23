"""Testes para o modelo AuditLog."""
from ..base import BaseModelTestCase
from ...models import AuditLog


class AuditLogModelTest(BaseModelTestCase):
    """Testes para o modelo AuditLog."""
    
    def test_audit_log_creation(self):
        """Testa a criação de log de auditoria."""
        audit = AuditLog.objects.create(
            user=self.user,
            action='LOGIN',
            description='Teste de login',
            ip_address='127.0.0.1',
            user_agent='TestAgent'
        )
        
        self.assertEqual(audit.user, self.user)
        self.assertEqual(audit.action, 'LOGIN')
        self.assertEqual(audit.description, 'Teste de login')
        self.assertEqual(audit.ip_address, '127.0.0.1')
        self.assertEqual(audit.user_agent, 'TestAgent')
    
    def test_audit_log_str(self):
        """Testa a representação string do log de auditoria."""
        audit = AuditLog.objects.create(
            user=self.user,
            action='LOGIN',
            description='Teste de login',
            ip_address='127.0.0.1',
            user_agent='TestAgent'
        )
        
        # O método __str__ inclui username, action display e timestamp
        str_repr = str(audit)
        self.assertIn(self.user.username, str_repr)
        self.assertIn('Login', str_repr)  # get_action_display() para LOGIN
        self.assertIn('-', str_repr)  # Separadores
    
    def test_audit_log_timestamp(self):
        """Testa se o timestamp é criado automaticamente."""
        audit = AuditLog.objects.create(
            user=self.user,
            action='LOGIN',
            description='Teste de login',
            ip_address='127.0.0.1',
            user_agent='TestAgent'
        )
        
        self.assertIsNotNone(audit.timestamp)
    
    def test_audit_log_without_user(self):
        """Testa criação de log sem usuário (para ações do sistema)."""
        audit = AuditLog.objects.create(
            action='SYSTEM_START',
            description='Sistema iniciado',
            ip_address='127.0.0.1',
            user_agent='SystemAgent'
        )
        
        self.assertIsNone(audit.user)
        self.assertEqual(audit.action, 'SYSTEM_START')
    
    def test_audit_log_ordering(self):
        """Testa se os logs são ordenados por timestamp."""
        # Cria vários logs
        audit1 = AuditLog.objects.create(
            user=self.user,
            action='LOGIN',
            description='Primeiro login',
            ip_address='127.0.0.1'
        )
        
        audit2 = AuditLog.objects.create(
            user=self.user,
            action='LOGOUT',
            description='Primeiro logout',
            ip_address='127.0.0.1'
        )
        
        # Verifica ordenação (mais recente primeiro)
        logs = AuditLog.objects.all()
        self.assertEqual(logs[0], audit2)  # Mais recente
        self.assertEqual(logs[1], audit1)  # Mais antigo
