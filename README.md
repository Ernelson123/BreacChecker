# Breach Checker

Verificador seguro de credenciais comprometidas via HaveIBeenPwned API.

**Ainda em desenvolvimento**

**Python 3.13 · Go 1.25 · uv · k-Anonymity · HaveIBeenPwned API**

---

## 🚀 Funcionalidades

| Comando | Descrição | Chave API | Privacidade |
|---------|-----------|-----------|-------------|
| `check-pwd` | Verifica passwords via k-Anonymity |  Não necessária | Password nunca sai do dispositivo |
| `check-mail` | Verifica emails em vazamentos |  Necessária |  Email enviado via TLS |
| `check-domain` | Scan de domínio corporativo (Go) |  Necessária |  Milhares de emails em paralelo |

---

## Instalação

### Pré-requisitos

| Ferramenta | Versão Mínima |
|-----------|--------------|
| Python | 3.13+ | 
| uv | 0.7+ |
| Go | 1.25+ | 
| Git | 2.40+ | 

### Setup Rápido

```bash
# 1. Clonar repositório
git clone https://github.com/teu-user/breach-checker.git
cd breach-checker

# 2. Instalar dependências
uv sync --extra dev

# 3. Build do scanner Go (opcional, para check-domain)
make build-scanner

# 4. Verificar instalação
uv run breach-checker --help

### Uso - Verificar Password grátis
uv run breach-checker check-pwd

### - output esperado--ex.
╭────────────────────────────────────────────────────╮
│ COMPROMETIDA                                        │
│ Encontrada 3,861,493 vezes em vazamentos.          │
╰────────────────────────────────────────────────────╯

### Verificar email
# Definir chave API (obter em https://haveibeenpwned.com/API/Key)
export HIBP_API_KEY=sua_chave_aqui

# Ou usar ficheiro .env
echo "HIBP_API_KEY=sua_chave_aqui" >> .env

# Verificar email
uv run breach-checker check-mail email@exemplo.com


### Verificar dominio corporativo
# Requer scanner Go compilado
make build-scanner

# Verificar domínio
uv run breach-checker check-domain empresa.com

# Com concorrência personalizada
uv run breach-checker check-domain empresa.com --concurrency 50

### TESTES
# Todos os testes (Python + Go)
make test

# Só Python
uv run pytest tests/ -v --cov=src/breach_checker

# Só Go
cd scanner && go test ./... -v

# Com relatório de cobertura HTML
uv run pytest tests/ --cov=src/breach_checker --cov-report=html
# Abrir: firefox htmlcov/index.html

### NixOS
# Entrar no ambiente flake
nix develop

# Ou shell temporário
nix-shell -p uv go_1_25 git

###Ubuntu/Debian
# Instalar uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"

# Instalar Go
sudo apt install golang-go

# Verificar
uv --version
go version

### macOS
# Instalar uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"

# Instalar Go
brew install go

# Verificar
uv --version
go version

###Windows
# Instalar uv
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Instalar Go
winget install GoLang.Go

# Verificar
uv --version
go version
