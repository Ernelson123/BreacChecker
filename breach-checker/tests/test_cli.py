import os
import pytest
from typer.testing import CliRunner
from breach_checker.cli import app

runner = CliRunner()

@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Remover variáveis de ambiente sensíveis antes de cada teste."""
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    yield

class TestCheckPwd:
    """Testes para o comando check-pwd."""

    def test_check_pwd_help(self):
        """--help deve mostrar documentação."""
        result = runner.invoke(app, ["check-pwd", "--help"])
        assert result.exit_code == 0
        assert "password" in result.output.lower()

    def test_check_pwd_empty_password(self, monkeypatch):
        """Password vazia deve retornar erro."""
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "")
        result = runner.invoke(app, ["check-pwd"])
        assert result.exit_code == 1
        assert "password vazia" in result.output.lower()


class TestCheckMail:
    """Testes para o comando check-mail."""

    def test_check_mail_help(self):
        """--help deve mostrar documentação."""
        result = runner.invoke(app, ["check-mail", "--help"])
        assert result.exit_code == 0
        assert "email" in result.output.lower()

    def test_check_mail_no_api_key(self, monkeypatch):
        """Sem chave API deve retornar erro."""
        # Remover HIBP_API_KEY do ambiente para este teste
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        
        result = runner.invoke(app, ["check-mail", "test@example.com"])
        assert result.exit_code == 1
        assert "HIBP_API_KEY" in result.output
