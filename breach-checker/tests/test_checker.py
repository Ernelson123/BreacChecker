
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

class TestCheckEmail:
    """Testes para a funçaõ check_email"""

    @pytest.mark.asyncio
    async def test_email_not_found_returns_empty(self, httpx_mock: HTTPXMock):
        """404 deve retornar BeachResult com lista vazia(não é erro)."""
        httpx_mock.add_response(status_code=404)

        result = await check_email('novo@gmail', 'test-api-key')

        assert result.is_compromised is False
        assert result.breach_count == 0
        assert result.breaches == []

    @pytest.mark.asyncio
    async def test_email_found_returns_breaches(self, httpx_mock: HTTPXMock):
        """200 com JSON deve retornar lista de vazamentos."""
        httpx_mock.add_response(
            json=[
                {
                    'Name': 'Adobe',
                    'Domain': 'adobe.com',
                    'BreachDate': '2013-10-01',
                    'PwnCount': 152000000,
                    'Description': 'Vazamento da Adobe',
                    'IsVerified': True,
                    'DataClasses': ['Emails', 'Passwords'], 
                }
            ]
        )

        result = await check_email('test@example.com', 'test-api-key')

        assert result.is_compromised is True
        assert result.breach_count == 1
        assert result.breaches[0].name == 'Adobe'
        assert result.breaches[0].is_verified is True

    @pytest.mark.asyncio
    async def test_api_key_sent_in_header(self, httpx_mock: HTTPXMock):
        """Chave API deve ser enviada no Header 'hibp-ap-key'."""
        httpx_mock.add_response(status_code=404)

        await check_email('test@example.com', 'minha-chave-secreta')

        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        headers = requests[0].headers
        assert headers.get('hibp-api-key') == 'minha-chave-secreta'

    @pytest.mark.asyncio
    async def test_user_agent_sent(self, httpx_mock: HTTPXMock):
        """User-Agent deve ser enviado no header."""
        httpx_mock.add_response(status_code=404)
        
        await check_email('test@example.com', 'test-key')
        
        requests = httpx_mock.get_requests()
        headers = requests[0].headers
        assert 'BreachChecker' in headers.get('User-Agent', '')
    
    @pytest.mark.asyncio
    async def test_truncate_response_false(self, httpx_mock: HTTPXMock):
        """Parâmetro truncateResponse=false deve ser enviado."""
        httpx_mock.add_response(status_code=404)
        
        await check_email('test@example.com', 'test-key')
        
        requests = httpx_mock.get_requests()
        url = str(requests[0].url)
        assert 'truncateResponse=false' in url