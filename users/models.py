from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserProfile(models.Model):
    """
    Modelo estendido para informações adicionais do usuário.
    
    Este modelo pode ser usado para adicionar campos personalizados
    como CPF, telefone, endereço, etc.
    """
    
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        verbose_name='Usuário'
    )
    
    # Campos de identificação
    full_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name='Nome Completo'
    )
    
    cpf = models.CharField(
        max_length=14,
        blank=True,
        null=True,
        unique=True,
        validators=[
            RegexValidator(
                regex=r'^\d{3}\.\d{3}\.\d{3}-\d{2}$|^\d{11}$',
                message='CPF deve estar no formato XXX.XXX.XXX-XX ou apenas números'
            )
        ],
        verbose_name='CPF'
    )
    
    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r'^\+?1?\d{9,15}$',
                message='Número de telefone deve estar em formato válido'
            )
        ],
        verbose_name='Telefone'
    )
    
    date_of_birth = models.DateField(
        blank=True,
        null=True,
        verbose_name='Data de Nascimento'
    )
    
    bio = models.TextField(
        blank=True,
        null=True,
        verbose_name='Biografia'
    )
    
    # Campos de endereço
    address = models.TextField(
        blank=True,
        null=True,
        verbose_name='Endereço'
    )
    
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name='Cidade'
    )
    
    state = models.CharField(
        max_length=2,
        blank=True,
        null=True,
        verbose_name='Estado'
    )
    
    zip_code = models.CharField(
        max_length=10,
        blank=True,
        null=True,
        verbose_name='CEP'
    )
    
    # Campos de preferências
    timezone = models.CharField(
        max_length=50,
        default='America/Sao_Paulo',
        verbose_name='Fuso Horário'
    )
    
    language = models.CharField(
        max_length=10,
        default='pt-br',
        choices=[
            ('pt-br', 'Português (Brasil)'),
            ('en', 'English'),
            ('es', 'Español'),
        ],
        verbose_name='Idioma'
    )
    
    # Campos de auditoria
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Criado em'
    )
    
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Atualizado em'
    )
    
    # Campos de controle
    is_verified = models.BooleanField(
        default=False,
        verbose_name='Verificado'
    )
    
    verification_token = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name='Token de Verificação'
    )
    
    class Meta:
        verbose_name = 'Perfil de Usuário'
        verbose_name_plural = 'Perfis de Usuários'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Perfil de {self.user.username}"
    
    @property
    def full_address(self):
        """Retorna o endereço completo formatado."""
        parts = [
            self.address,
            self.city,
            self.state,
            self.zip_code
        ]
        return ', '.join(filter(None, parts)) or None
    
    def save(self, *args, **kwargs):
        """Normaliza o CPF antes de salvar."""
        if self.cpf:
            # Remove pontuação do CPF
            self.cpf = ''.join(filter(str.isdigit, self.cpf))
            # Formata o CPF
            if len(self.cpf) == 11:
                self.cpf = f"{self.cpf[:3]}.{self.cpf[3:6]}.{self.cpf[6:9]}-{self.cpf[9:]}"
        
        super().save(*args, **kwargs)


class AuditLog(models.Model):
    """
    Modelo para auditoria de ações dos usuários.
    
    Registra todas as ações importantes realizadas pelos usuários
    para fins de segurança e compliance.
    """
    
    ACTION_CHOICES = [
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('PASSWORD_CHANGE', 'Alteração de Senha'),
        ('PROFILE_UPDATE', 'Atualização de Perfil'),
        ('PERMISSION_CHANGE', 'Alteração de Permissão'),
        ('ACCOUNT_CREATION', 'Criação de Conta'),
        ('ACCOUNT_DELETION', 'Exclusão de Conta'),
        ('TOKEN_REFRESH', 'Refresh de Token'),
        ('FAILED_LOGIN', 'Tentativa de Login Falhada'),
    ]
    
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        verbose_name='Usuário'
    )
    
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        verbose_name='Ação'
    )
    
    description = models.TextField(
        blank=True,
        null=True,
        verbose_name='Descrição'
    )
    
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name='Endereço IP'
    )
    
    user_agent = models.TextField(
        blank=True,
        null=True,
        verbose_name='User Agent'
    )
    
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Data/Hora'
    )
    
    additional_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name='Dados Adicionais'
    )
    
    class Meta:
        verbose_name = 'Log de Auditoria'
        verbose_name_plural = 'Logs de Auditoria'
        ordering = ['-timestamp']
    
    def __str__(self):
        username = self.user.username if self.user else 'Usuário Anônimo'
        return f"{username} - {self.get_action_display()} - {self.timestamp}"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal para criar automaticamente um UserProfile quando um User é criado.
    """
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal para salvar o UserProfile quando o User é salvo.
    """
    if hasattr(instance, 'profile'):
        instance.profile.save()
