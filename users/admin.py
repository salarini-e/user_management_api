from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile, AuditLog


class UserProfileInline(admin.StackedInline):
    """Inline para o perfil do usuário."""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Perfil'
    fk_name = 'user'


class UserAdmin(BaseUserAdmin):
    """Admin customizado para o modelo User."""
    inlines = (UserProfileInline,)
    
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(UserAdmin, self).get_inline_instances(request, obj)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin para o modelo UserProfile."""
    list_display = [
        'user',
        'cpf',
        'phone',
        'city',
        'state',
        'is_verified',
        'created_at'
    ]
    list_filter = [
        'is_verified',
        'state',
        'language',
        'created_at'
    ]
    search_fields = [
        'user__username',
        'user__email',
        'user__first_name',
        'user__last_name',
        'cpf',
        'phone'
    ]
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Usuário', {
            'fields': ('user',)
        }),
        ('Identificação', {
            'fields': ('cpf', 'phone')
        }),
        ('Endereço', {
            'fields': ('address', 'city', 'state', 'zip_code'),
            'classes': ('collapse',)
        }),
        ('Preferências', {
            'fields': ('timezone', 'language'),
            'classes': ('collapse',)
        }),
        ('Verificação', {
            'fields': ('is_verified', 'verification_token'),
            'classes': ('collapse',)
        }),
        ('Auditoria', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin para o modelo AuditLog."""
    list_display = [
        'user',
        'action',
        'ip_address',
        'timestamp'
    ]
    list_filter = [
        'action',
        'timestamp'
    ]
    search_fields = [
        'user__username',
        'user__email',
        'description',
        'ip_address'
    ]
    readonly_fields = [
        'user',
        'action',
        'description',
        'ip_address',
        'user_agent',
        'timestamp',
        'additional_data'
    ]
    
    def has_add_permission(self, request):
        """Remove a permissão de adicionar logs manualmente."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Remove a permissão de editar logs."""
        return False


# Re-registra o modelo User com o admin customizado
admin.site.unregister(User)
admin.site.register(User, UserAdmin)
