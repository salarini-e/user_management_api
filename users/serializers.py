from rest_framework import serializers
from django.contrib.auth.models import User, Group
from .models import UserProfile


class GroupSerializer(serializers.ModelSerializer):
    """Serializador para os grupos do usuário."""
    
    class Meta:
        model = Group
        fields = ['id', 'name']


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializador para o perfil estendido do usuário."""
    
    full_address = serializers.ReadOnlyField()
    
    class Meta:
        model = UserProfile
        fields = [
            'full_name',
            'cpf',
            'phone',
            'date_of_birth',
            'bio',
            'address',
            'city',
            'state',
            'zip_code',
            'full_address',
            'timezone',
            'language',
            'is_verified'
        ]
        read_only_fields = ['is_verified']


class UserSerializer(serializers.ModelSerializer):
    """Serializador para o modelo de usuário Django."""
    
    groups = GroupSerializer(many=True, read_only=True)
    full_name = serializers.SerializerMethodField()
    profile = UserProfileSerializer(read_only=False)
    
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'full_name',
            'is_active',
            'groups',
            'profile',
            'date_joined',
            'last_login'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']
    
    def get_full_name(self, obj):
        """Retorna o nome completo do usuário."""
        if obj.first_name and obj.last_name:
            return f"{obj.first_name} {obj.last_name}".strip()
        return obj.username
    
    def update(self, instance, validated_data):
        """Atualiza o usuário e seu perfil."""
        profile_data = validated_data.pop('profile', None)
        
        # Atualiza campos do User
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Atualiza campos do Profile se fornecidos
        if profile_data:
            profile = instance.profile
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()
        
        return instance


class UserLoginSerializer(serializers.Serializer):
    """Serializador para login de usuário."""
    
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)
    
    def validate_username(self, value):
        """Permite login com username, email ou CPF (extensível)."""
        return value.lower().strip()


class TokenResponseSerializer(serializers.Serializer):
    """Serializador para resposta de tokens JWT."""
    
    access = serializers.CharField()
    refresh = serializers.CharField()
    user = UserSerializer(read_only=True)
    expires_in = serializers.IntegerField(help_text="Tempo de expiração do access token em segundos")
