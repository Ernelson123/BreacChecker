"""Verificador de credenciais comprometidas via HaveIBeenPwned API."""

import hashlib
import httpx
from breach_checker.models import PasswordResult, BreachResult, Breach

HIBP_PWNED_URL = 'https://api.pwnedpasswords.com/range/{prefix}'
HIBP_EMAIL_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
USER_AGENT = 'BreachChecker/0.1.0 (projeto educacional)'


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


async def check_password(password: str) -> PasswordResult:
    """Verifica se uma password foi comprometida via k-Anonymity."""
    prefix, suffix = _hash_password(password)
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            HIBP_PWNED_URL.format(prefix=prefix),
            headers={'Add-Padding': 'true'},
            timeout=10.0,
        )
        resp.raise_for_status()
    
    count = _parse_hibp_response(resp.text).get(suffix, 0)
    
    return PasswordResult(
        hash_prefix=prefix,
        is_compromised=count > 0,
        occurrence_count=count,
    )


async def check_email(email: str, api_key: str) -> BreachResult:
    """Verifica se email aparece em vazamentos."""
    email_hash = _hash_email_for_cache(email)
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            HIBP_EMAIL_URL.format(email=email),
            headers={'hibp-api-key': api_key, 'User-Agent': USER_AGENT},
            params={'truncateResponse': 'false'},
            timeout=10.0,
        )
        
        if resp.status_code == 404:
            return BreachResult(email_hash=email_hash, breaches=[])
        
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
    
    return BreachResult(email_hash=email_hash, breaches=breaches)