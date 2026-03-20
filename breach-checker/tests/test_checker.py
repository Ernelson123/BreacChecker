
"""Testes para o módulo checker.py."""

import pytest
from pytest_httpx import HTTPXMock
from breach_checker.checker import _hash_password, check_password


class TestHashPassword:
    """Testes para a função _hash_password."""
    
    def test_hash_prefix_has_5_chars(self):
        """O prefixo deve ter exatamente 5 caracteres."""
        prefix, suffix = _hash_password('password')
        assert len(prefix) == 5
        assert len(suffix) == 35
    
    def test_known_hash_prefix(self):
        """SHA-1 de 'password' começa com '5BAA6'."""
        prefix, _ = _hash_password('password')
        assert prefix == '5BAA6'


class TestCheckPassword:
    """Testes para a função check_password."""
    
    @pytest.mark.asyncio
    async def test_password_never_sent_to_network(self, httpx_mock: HTTPXMock):
        """A password completa NUNCA deve ser enviada para a rede."""
        prefix, suffix = _hash_password('supersecreta')
        httpx_mock.add_response(text='')
        
        await check_password('supersecreta')
        
        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        url = str(requests[0].url)
        
        assert suffix not in url
        assert 'supersecreta' not in url
        assert prefix in url
    
    @pytest.mark.asyncio
    async def test_compromised_password(self, httpx_mock: HTTPXMock):
        """Password comprometida deve retornar is_compromised=True."""
        prefix, suffix = _hash_password('password')
        httpx_mock.add_response(text=f'{suffix}:3861493\nOUTRO:5')
        
        result = await check_password('password')
        
        assert result.is_compromised is True
        assert result.occurrence_count == 3861493