import pytest
import hashlib
from pytest_httpx import HTTPXMock

from breach_checker.checker import (
    _hash_password,
    _parse_hibp_response,
    check_password,
    _hash_email_for_cache,
)
from breach_checker.models import PasswordResult, BreachResult, Breach


class TestHashPassword:
    """Testes para a função _hash_password."""

    def test_hash_prefix_has_5_chars(self):
        """Prefixo deve ter exatamente 5 caracteres."""
        prefix, suffix = _hash_password("password")
        assert len(prefix) == 5
        assert len(suffix) == 35

    def test_hash_is_uppercase(self):
        """Hash deve estar em maiúsculas."""
        prefix, suffix = _hash_password("password")
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()

    def test_known_hash_prefix(self):
        """SHA-1 de 'password' começa com '5BAA6'."""
        prefix, _ = _hash_password("password")
        assert prefix == "5BAA6"

    def test_same_password_same_hash(self):
        """Mesma password deve produzir mesmo hash."""
        prefix1, suffix1 = _hash_password("test123")
        prefix2, suffix2 = _hash_password("test123")
        assert prefix1 == prefix2
        assert suffix1 == suffix2

    def test_different_password_different_hash(self):
        """Passwords diferentes devem produzir hashes diferentes."""
        prefix1, _ = _hash_password("password1")
        prefix2, _ = _hash_password("password2")
        assert prefix1 != prefix2


class TestParseHIBPResponse:
    """Testes para a função _parse_hibp_response."""

    def test_parse_single_hash(self):
        """Parser deve extrair sufixo e contagem."""
        text = "C6008F9CAB4083784CBD1874F76618D2A97:3861493"
        result = _parse_hibp_response(text)
        assert "C6008F9CAB4083784CBD1874F76618D2A97" in result
        assert result["C6008F9CAB4083784CBD1874F76618D2A97"] == 3861493

    def test_parse_multiple_hashes(self):
        """Parser deve extrair múltiplos hashes."""
        text = "HASH1:100\nHASH2:200\nHASH3:300"
        result = _parse_hibp_response(text)
        assert len(result) == 3
        assert result["HASH1"] == 100
        assert result["HASH2"] == 200
        assert result["HASH3"] == 300

    def test_parse_empty_response(self):
        """Resposta vazia deve retornar dict vazio."""
        result = _parse_hibp_response("")
        assert result == {}

    def test_parse_invalid_lines_ignored(self):
        """Linhas inválidas devem ser ignoradas."""
        text = "HASH1:100\nLINHA_INVALIDA\nHASH2:200"
        result = _parse_hibp_response(text)
        assert len(result) == 2


class TestCheckPassword:
    """Testes para a função check_password."""

    @pytest.mark.asyncio
    async def test_password_never_sent_to_network(self, httpx_mock: HTTPXMock):
        """Password completa NUNCA deve ser enviada para a rede."""
        prefix, suffix = _hash_password("supersecreta")
        httpx_mock.add_response(text="")

        await check_password("supersecreta")

        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        url = str(requests[0].url)

        # Sufixo NÃO deve estar na URL
        assert suffix not in url
        # Password em claro NÃO deve estar na URL
        assert "supersecreta" not in url
        # Apenas prefixo deve estar na URL
        assert prefix in url

    @pytest.mark.asyncio
    async def test_compromised_password(self, httpx_mock: HTTPXMock):
        """Password comprometida deve retornar is_compromised=True."""
        prefix, suffix = _hash_password("password")
        httpx_mock.add_response(text=f"{suffix}:3861493\nOUTRO:5")

        result = await check_password("password")

        assert result.is_compromised is True
        assert result.occurrence_count == 3861493
        assert result.hash_prefix == prefix

    @pytest.mark.asyncio
    async def test_safe_password(self, httpx_mock: HTTPXMock):
        """Password segura deve retornar is_compromised=False."""
        httpx_mock.add_response(text="OUTROHASH:5")

        result = await check_password("xK9#mP2$nQ7@wL")

        assert result.is_compromised is False
        assert result.occurrence_count == 0

    @pytest.mark.asyncio
    async def test_add_padding_header(self, httpx_mock: HTTPXMock):
        """Header 'Add-Padding' deve ser enviado para privacidade."""
        httpx_mock.add_response(text="")

        await check_password("test")

        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        headers = requests[0].headers
        assert headers.get("Add-Padding") == "true"


class TestHashEmailForCache:
    """Testes para a função _hash_email_for_cache."""

    def test_hash_is_sha256(self):
        """Hash do email deve ser SHA-256 (64 chars hex)."""
        email_hash = _hash_email_for_cache("test@example.com")
        assert len(email_hash) == 64

    def test_case_insensitive(self):
        """Email deve ser normalizado para lowercase."""
        hash1 = _hash_email_for_cache("Test@Example.com")
        hash2 = _hash_email_for_cache("test@example.com")
        assert hash1 == hash2

    def test_same_email_same_hash(self):
        """Mesmo email deve produzir mesmo hash."""
        hash1 = _hash_email_for_cache("user@domain.com")
        hash2 = _hash_email_for_cache("user@domain.com")
        assert hash1 == hash2

    def test_different_email_different_hash(self):
        """Emails diferentes devem produzir hashes diferentes."""
        hash1 = _hash_email_for_cache("user1@domain.com")
        hash2 = _hash_email_for_cache("user2@domain.com")
        assert hash1 != hash2