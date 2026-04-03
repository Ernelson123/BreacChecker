set -e # Para o script se algum comando falhar

echo "🛡️  Breach Checker - Verificação de Ambiente"
echo "---------------------------------------------"

# Função helper para check
check_cmd() {
    if command -v $1 &> /dev/null; then
        echo "✅ $1: $($1 --version | head -n1)"
    else
        echo "❌ $1: NÃO ENCONTRADO"
        return 1
    fi
}

check_cmd uv
check_cmd git

# Check Python via uv
echo -n "✅ Python (uv): "
uv run python --version || echo "❌ Falha"

# Check Git Config
if [ -z "$(git config user.name)" ]; then
    echo "❌ Git User Name não configurado"
else
    echo "✅ Git User: $(git config user.name)"
fi

echo "---------------------------------------------"
echo "Se todos estiverem ✅, pode avançar para a Fase 1!"