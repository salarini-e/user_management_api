"""
Testes para a aplicação users.

Esta estrutura organiza os testes por contexto e funcionalidade:

- auth/: Testes de autenticação e autorização
- models/: Testes de modelos de dados
- serializers/: Testes de serialização/validação
- api/: Testes de endpoints da API
- security/: Testes de segurança específicos
- integration/: Testes de integração completos

Estrutura:
    tests/
    ├── __init__.py
    ├── base.py                     # Classes base e utilitários
    ├── auth/
    │   ├── __init__.py
    │   ├── test_login.py          # Testes de login
    │   ├── test_logout.py         # Testes de logout
    │   ├── test_tokens.py         # Testes de tokens JWT
    │   └── test_permissions.py    # Testes de permissões
    ├── models/
    │   ├── __init__.py
    │   ├── test_user_profile.py   # Testes do modelo UserProfile
    │   └── test_audit_log.py      # Testes do modelo AuditLog
    ├── serializers/
    │   ├── __init__.py
    │   ├── test_user_serializer.py
    │   ├── test_profile_serializer.py
    │   └── test_validation.py     # Testes de validação
    ├── api/
    │   ├── __init__.py
    │   ├── test_user_profile_api.py
    │   └── test_health_check.py
    ├── security/
    │   ├── __init__.py
    │   ├── test_cors_csrf.py      # Testes CORS/CSRF
    │   ├── test_token_security.py # Segurança de tokens
    │   └── test_rate_limiting.py  # Rate limiting
    └── integration/
        ├── __init__.py
        └── test_complete_flows.py # Fluxos completos
"""
