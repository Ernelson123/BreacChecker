# Changelog

Todas as alterações notáveis neste projeto serão documentadas neste ficheiro.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [Não Lançado]

### Adicionado
- Fase 6: Microserviço Go para scan de domínios corporativos
- Fase 5: Cache local com TTL de 24h e permissões 600
- Fase 5: Retry com backoff exponencial e jitter
- Fase 4: CLI com Rich e Typer
- Fase 3: Integração com API HIBP para emails
- Fase 2: Verificação de passwords com k-Anonymity
- CI/CD com GitHub Actions (Python + Go + secrets-check)

### Segurança
- Passwords nunca saem do dispositivo (k-Anonymity)
- Cache local com permissões restritivas (0o600)
- Sem secrets hardcoded no código
- Verificação automática de secrets no CI/CD

## [0.1.0] — 2026-03-29

### Adicionado
- Estrutura inicial do projeto com uv
- Python 3.13+
- Go 1.25+ para Fase 6
- Documentação completa (README.md)
- Licença MIT

### Técnico
- httpx >=0.28.1
- typer >=0.15.0
- rich >=14.0.0
- pydantic >=2.11.0
- pytest >=8.3.0
- ruff >=0.8.0
- mypy >=1.13.0