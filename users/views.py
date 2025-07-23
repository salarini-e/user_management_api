import logging
from datetime import datetime

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.utils import timezone

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView

from .serializers import UserLoginSerializer, UserSerializer, TokenResponseSerializer

logger = logging.getLogger(__name__)


class LoginView(APIView):
    """
    View para autenticação de usuários com JWT.
    
    Aceita POST com username e password, autentica o usuário,
    gera tokens JWT e retorna os tokens no corpo da resposta
    além de definir o access token em um cookie seguro.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        # Log da tentativa de login (sem dados sensíveis)
        logger.info(f"Tentativa de login para IP: {self.get_client_ip(request)}")
        
        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(f"Dados de login inválidos para IP: {self.get_client_ip(request)}")
            return Response(
                {'error': 'Dados inválidos', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # Tenta autenticar com username/email
        user = self.authenticate_user(username, password)
        
        if user == 'INACTIVE':
            logger.warning(f"Tentativa de login com usuário inativo: {username}")
            return Response(
                {'error': 'Conta desativada'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if user is None:
            logger.warning(f"Falha na autenticação para username: {username}")
            return Response(
                {'error': 'Credenciais inválidas'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Gera os tokens JWT
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        # Adiciona claims customizados ao payload
        access_token['full_name'] = f"{user.first_name} {user.last_name}".strip() or user.username
        access_token['groups'] = [group.name for group in user.groups.all()]
        access_token['email'] = user.email
        
        # Atualiza o último login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Prepara a resposta
        user_serializer = UserSerializer(user)
        response_data = {
            'access': str(access_token),
            'refresh': str(refresh),
            'user': user_serializer.data,
            'expires_in': settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()
        }
        
        response = Response(response_data, status=status.HTTP_200_OK)
        
        # Define o access token em um cookie seguro
        response.set_cookie(
            settings.AUTH_COOKIE_NAME,
            str(access_token),
            max_age=settings.AUTH_COOKIE_MAX_AGE,
            secure=settings.AUTH_COOKIE_SECURE,
            httponly=settings.AUTH_COOKIE_HTTP_ONLY,
            samesite=settings.AUTH_COOKIE_SAMESITE,
            path=settings.AUTH_COOKIE_PATH
        )
        
        logger.info(f"Login bem-sucedido para usuário: {user.username}")
        return response
    
    def authenticate_user(self, username, password):
        """
        Autentica usuário por username ou email.
        Extensível para CPF no futuro.
        """
        user_obj = None
        
        # Primeiro, tenta encontrar o usuário por username
        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            # Se não encontrar por username, tenta por email
            try:
                user_obj = User.objects.get(email=username)
            except User.DoesNotExist:
                return None
        
        # Se encontrou o usuário, verifica se está ativo antes de autenticar
        if user_obj and not user_obj.is_active:
            # Retorna um objeto especial para indicar que o usuário está inativo
            return 'INACTIVE'
        
        # Autentica com username
        user = authenticate(username=user_obj.username, password=password)
        return user
    
    def get_client_ip(self, request):
        """Obtém o IP do cliente."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class TokenRefreshView(BaseTokenRefreshView):
    """
    View personalizada para refresh de tokens JWT.
    
    Extends a view padrão do SimpleJWT para adicionar
    funcionalidades customizadas se necessário.
    """
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Atualiza o cookie com o novo access token se necessário
            access_token = response.data.get('access')
            if access_token:
                response.set_cookie(
                    settings.AUTH_COOKIE_NAME,
                    access_token,
                    max_age=settings.AUTH_COOKIE_MAX_AGE,
                    secure=settings.AUTH_COOKIE_SECURE,
                    httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                    samesite=settings.AUTH_COOKIE_SAMESITE,
                    path=settings.AUTH_COOKIE_PATH
                )
        
        return response


class UserProfileView(APIView):
    """
    View para retornar os dados do usuário autenticado.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Retorna os dados do usuário autenticado."""
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    def patch(self, request):
        """Atualiza os dados do usuário autenticado."""
        serializer = UserSerializer(
            request.user, 
            data=request.data, 
            partial=True
        )
        
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Perfil atualizado para usuário: {request.user.username}")
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    View para logout do usuário.
    
    Remove o cookie de autenticação e invalida o refresh token.
    """
    try:
        # Tenta obter o refresh token do corpo da requisição
        refresh_token = request.data.get('refresh')
        
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as blacklist_error:
                # Log do erro mas não falha o logout se o token já estiver na blacklist
                logger.warning(f"Erro ao adicionar token à blacklist: {str(blacklist_error)}")
        
        response = JsonResponse({'message': 'Logout realizado com sucesso'})
        
        # Remove o cookie de autenticação
        response.delete_cookie(
            settings.AUTH_COOKIE_NAME,
            path=settings.AUTH_COOKIE_PATH
        )
        
        logger.info(f"Logout realizado para usuário: {request.user.username}")
        return response
        
    except Exception as e:
        logger.error(f"Erro durante logout: {str(e)}")
        return JsonResponse(
            {'error': 'Erro interno do servidor'}, 
            status=500
        )


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    View para verificação de saúde da API.
    """
    return Response({
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'version': '1.0.0'
    })
