"""Modelos de dados para o Breach Checker."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PasswordResult:
    """Resultado da verificação de password."""
    hash_prefix: str
    is_compromised: bool
    occurrence_count: int


@dataclass(frozen=True)
class Breach:
    """Informações sobre um vazamento específico."""
    name: str
    domain: str
    breach_date: str
    pwn_count: int
    description: str
    is_verified: bool
    data_classes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BreachResult:
    """Resultado da verificação de email."""
    email_hash: str
    breaches: list[Breach]
    
    @property
    def is_compromised(self) -> bool:
        return len(self.breaches) > 0
    
    @property
    def breach_count(self) -> int:
        return len(self.breaches)