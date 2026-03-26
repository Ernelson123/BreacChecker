import hashlib
import httpx
import time
import random
import asyncio
from typing import Optional

from breach_checker.models import PasswordResult, BreachResult, Breach
from breach_checker.cache import Cache

# URLs da API
HIBP_PWNED_URL = 'https://api.pwnedpasswords.com/range/{prefix}'
HIBP_EMAIL_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'

# User-Agent para identificar o cliente
USER_AGENT = 'BreachChecker/0.1.0 (projeto educacional)'

# Configurações de retry
MAX_RETRIES = 3
BASE_DELAY = 1.0
MAX_DELAY = 30.0
JITTER = 0.1

# Cache global (singleton)
_cache: Optional[Cache] = None


def get_cache() -> Cache:
    """Obter ou criar instância de cache singleton."""
    global _cache
    if _cache is None:
        _cache = Cache(ttl=86400)
    return _cache


def _calculate_delay(attempt: int) -> float:
    """Calcular delay com backoff exponencial e jitter."""
    delay = min(BASE_DELAY * (2 ** attempt), MAX_DELAY)
    jitter_range = delay * JITTER
    return delay + random.uniform(-jitter_range, jitter_range)


def _hash_password(password: str) -> tuple[str, str]:
    """Calcula SHA-1 da password e divide em prefixo (5 chars) + sufixo (35 chars)."""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1[:5], sha1[5:]


def _parse_hibp_response(text: str) -> dict[str, int]:
    """Converte resposta da API HIBP em dicionário {sufixo: contagem}."""
    result: dict[str, int] = {}
    for line in text.splitlines():
        if ':' not in line:
            continue
        suffix, count_str = line.split(':', 1)
        try:
            result[suffix.upper()] = int(count_str)
        except ValueError:
            continue
    return result


def _hash_email_for_cache(email: str) -> str:
    """Calcula SHA-256 do email para uso como chave de cache."""
    return hashlib.sha256(email.lower().encode('utf-8')).hexdigest()


async def check_password(password: str, use_cache: bool = True) -> PasswordResult:
    """Verifica se uma password foi comprometida via k-Anonymity."""
    prefix, suffix = _hash_password(password)
    password_hash = prefix + suffix
    
    # Verificar cache primeiro
    if use_cache:
        cached_result = get_cache().get_password(password_hash)
        if cached_result is not None:
            return cached_result
    
    # Retry com backoff exponencial
    last_exception = None
    for attempt in range(MAX_RETRIES):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    HIBP_PWNED_URL.format(prefix=prefix),
                    headers={'Add-Padding': 'true'},
                    timeout=10.0,
                )
                resp.raise_for_status()
            
            count = _parse_hibp_response(resp.text).get(suffix, 0)
            result = PasswordResult(
                hash_prefix=prefix,
                is_compromised=count > 0,
                occurrence_count=count,
            )
            
            if use_cache:
                get_cache().set_password(password_hash, result)
            
            return result
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                last_exception = e
                if attempt < MAX_RETRIES - 1:
                    delay = _calculate_delay(attempt)
                    await asyncio.sleep(delay)
                    continue
            raise
        
        except httpx.TimeoutException as e:
            last_exception = e
            if attempt < MAX_RETRIES - 1:
                delay = _calculate_delay(attempt)
                await asyncio.sleep(delay)
                continue
            raise
    
    if last_exception:
        raise last_exception
    
    raise RuntimeError("Unexpected error in check_password")


async def check_email(email: str, api_key: str, use_cache: bool = True) -> BreachResult:
    """Verifica se email aparece em vazamentos."""
    email_hash = _hash_email_for_cache(email)
    
    # Verificar cache primeiro
    if use_cache:
        cached_result = get_cache().get_email(email_hash)
        if cached_result is not None:
            return cached_result
    
    # Retry com backoff exponencial
    last_exception = None
    for attempt in range(MAX_RETRIES):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    HIBP_EMAIL_URL.format(email=email),
                    headers={
                        'hibp-api-key': api_key,
                        'User-Agent': USER_AGENT
                    },
                    params={'truncateResponse': 'false'},
                    timeout=10.0,
                )
                
                if resp.status_code == 404:
                    result = BreachResult(email_hash=email_hash, breaches=[])
                    if use_cache:
                        get_cache().set_email(email_hash, result)
                    return result
                
                resp.raise_for_status()
            
            breaches = [
                Breach(
                    name=b['Name'],
                    domain=b.get('Domain', ''),
                    breach_date=b.get('BreachDate', ''),
                    pwn_count=b.get('PwnCount', 0),
                    description=b.get('Description', ''),
                    is_verified=b.get('IsVerified', False),
                    data_classes=b.get('DataClasses', []),
                )
                for b in resp.json()
            ]
            
            result = BreachResult(email_hash=email_hash, breaches=breaches)
            
            if use_cache:
                get_cache().set_email(email_hash, result)
            
            return result
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 503):
                last_exception = e
                if attempt < MAX_RETRIES - 1:
                    delay = _calculate_delay(attempt)
                    await asyncio.sleep(delay)
                    continue
            raise
        
        except httpx.TimeoutException as e:
            last_exception = e
            if attempt < MAX_RETRIES - 1:
                delay = _calculate_delay(attempt)
                await asyncio.sleep(delay)
                continue
            raise
    
    if last_exception:
        raise last_exception
    
    raise RuntimeError("Unexpected error in check_email")