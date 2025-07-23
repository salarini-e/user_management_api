# User Management API

API centralizada de gerenciamento de usuários construída com Django REST Framework e autenticação JWT.

## Características

-  **Autenticação JWT** com SimpleJWT
-  **Cookies HttpOnly Secure** para armazenamento de tokens
-  **CORS configurado** para domínios específicos
-  **Perfil de usuário extensível** com auditoria
-  **Autenticação flexível** (username ou email)
-  **Logs detalhados** de segurança
-  **Refresh automático** de tokens

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/salarini-e/user_management_api.git
cd user_management_api
```

2. Crie e ative o ambiente virtual:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Configure as variáveis de ambiente:
```bash
cp .env.example .env
```
Edite o arquivo .env com suas configurações

5. Execute as migrações:
```bash
python manage.py migrate
```

6. Crie um superusuário:
```bash
python manage.py createsuperuser
```

7. Inicie o servidor:
```bash
python manage.py runserver
```

## Endpoints da API

###  Autenticação

#### `POST /api/login/`
Autentica um usuário e retorna tokens JWT.

**Request:**
```json
{
    "username": "seu_usuario",  // ou email
    "password": "sua_senha"
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "username": "usuario",
        "email": "usuario@example.com",
        "first_name": "Nome",
        "last_name": "Sobrenome",
        "is_active": true,
        "groups": ["admin"],
        "profile": {
            "full_name": "Nome Sobrenome",
            "phone": "+5511999999999",
            "date_of_birth": "1990-01-01",
            "bio": "Biografia do usuário"
        }
    },
    "expires_in": 3600
}
```

#### `POST /api/token/refresh/`
Atualiza o token de acesso usando o refresh token.

**Request:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

###  Usuário

#### `GET /api/user/`
Retorna os dados do usuário autenticado.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
    "id": 1,
    "username": "usuario",
    "email": "usuario@example.com",
    "first_name": "Nome",
    "last_name": "Sobrenome",
    "is_active": true,
    "groups": ["admin"],
    "profile": {
        "full_name": "Nome Sobrenome",
        "phone": "+5511999999999",
        "date_of_birth": "1990-01-01",
        "bio": "Biografia do usuário"
    }
}
```

#### `PATCH /api/user/`
Atualiza os dados do usuário autenticado.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
    "first_name": "Novo Nome",
    "profile": {
        "phone": "+5511888888888"
    }
}
```

#### `POST /api/logout/`
Realiza logout do usuário.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

###  Utilitários

#### `GET /api/health/`
Verifica a saúde da API.

**Response:**
```json
{
    "status": "healthy",
    "timestamp": "2025-07-23T10:30:00Z",
    "version": "1.0.0"
}
```

## Autenticação

### Tokens JWT

A API usa tokens JWT com as seguintes características:

- **Access Token**: Válido por 1 hora
- **Refresh Token**: Válido por 7 dias
- **Cookie Seguro**: Access token também armazenado em cookie HttpOnly

### Claims Customizados

O payload JWT inclui:
```json
{
    "user_id": 1,
    "username": "usuario",
    "email": "usuario@example.com",
    "full_name": "Nome Sobrenome",
    "groups": ["admin"],
    "exp": 1690977600,
    "iat": 1690974000
}
```

## Segurança

### CORS

Configurado para permitir apenas domínios confiáveis:

### Cookies

- **HttpOnly**: Previne acesso via JavaScript
- **Secure**: Apenas HTTPS em produção
- **SameSite**: Proteção CSRF

### Logs

Todos os eventos de autenticação são registrados:
- Tentativas de login
- Falhas de autenticação
- Logout de usuários
- Atualizações de perfil

## Modelos

### User (Django padrão)
- `id`: ID único
- `username`: Nome de usuário
- `email`: Email (único)
- `first_name`: Primeiro nome
- `last_name`: Último nome
- `is_active`: Status ativo

### UserProfile
- `user`: Relação 1:1 com User
- `full_name`: Nome completo
- `phone`: Telefone
- `date_of_birth`: Data de nascimento
- `bio`: Biografia
- `created_at`: Data de criação
- `updated_at`: Data de atualização

### AuditLog
- `user`: Usuário relacionado
- `action`: Ação realizada
- `details`: Detalhes da ação
- `ip_address`: Endereço IP
- `user_agent`: User Agent
- `timestamp`: Data/hora

## Configurações

### Variáveis de Ambiente

```env
# Segurança
SECRET_KEY=sua-chave-secreta
DEBUG=False

# CORS
ALLOWED_HOSTS=localhost,127.0.0.1,esalarini.com.br
CORS_ALLOWED_ORIGINS=https://esalarini.com.br

# Cookies
AUTH_COOKIE_SECURE=True
AUTH_COOKIE_HTTP_ONLY=True
AUTH_COOKIE_SAMESITE=Lax
```

## Extensibilidade

### Autenticação por CPF

Para adicionar autenticação por CPF, estenda o método `authenticate_user` em `LoginView`:

```python
def authenticate_user(self, username, password):
    # Código atual...
    
    # Adicione validação de CPF
    if self.is_valid_cpf(username):
        try:
            user_obj = User.objects.get(userprofile__cpf=username)
            user = authenticate(username=user_obj.username, password=password)
        except User.DoesNotExist:
            pass
```

### Permissões Customizadas

Adicione permissões no modelo `UserProfile`:

```python
class UserProfile(models.Model):
    # Campos existentes...
    permissions = models.JSONField(default=dict, blank=True)
```

## Uso como Serviço

Esta API foi projetada para ser um serviço centralizado de autenticação. Outros sistemas Django podem:

1. **Validar tokens** fazendo requisições para `/api/user/`
2. **Obter dados do usuário** via token JWT
3. **Integrar** usando bibliotecas de cliente HTTP

### Exemplo de Integração

```python
import requests

def validate_user_token(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get('https://<dominio-api>/api/user/', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    return None
```

## Desenvolvimento

### Executar Testes

```bash
python manage.py test
```

### Logs

Os logs são salvos em `django.log` e incluem:
- Tentativas de autenticação
- Erros de validação
- Atualizações de perfil
- Eventos de logout

### Debug

Para desenvolvimento, defina `DEBUG=True` no `.env`.


