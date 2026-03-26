"""Testes para retry com backoff exponencial."""

import pytest
from breach_checker.checker import _calculate_delay, MAX_RETRIES, BASE_DELAY, MAX_DELAY


class TestCalculateDelay:
    """Testes para a função _calculate_delay."""
    
    def test_delay_increases_exponentially(self):
        """Delay deve aumentar exponencialmente com cada tentativa."""
        delay_0 = _calculate_delay(0)
        delay_1 = _calculate_delay(1)
        delay_2 = _calculate_delay(2)
        
        # Cada delay deve ser aproximadamente o dobro do anterior
        # (com jitter, não é exato)
        assert delay_1 > delay_0
        assert delay_2 > delay_1
    
    def test_delay_respects_max(self):
        """Delay não deve exceder MAX_DELAY."""
        # Attempt 10 deve ser limitado a MAX_DELAY
        delay = _calculate_delay(10)
        assert delay <= MAX_DELAY
    
    def test_delay_has_jitter(self):
        """Delay deve ter jitter (variação aleatória)."""
        # Chamar múltiplas vezes para o mesmo attempt
        delays = [_calculate_delay(1) for _ in range(10)]
        
        # Devem haver variações (jitter)
        # Se todos forem iguais, o jitter não está a funcionar
        assert len(set(delays)) > 1
    
    def test_base_delay_is_correct(self):
        """Delay inicial deve ser próximo de BASE_DELAY."""
        delay = _calculate_delay(0)
        # Com 10% jitter, deve estar entre 0.9 e 1.1
        assert BASE_DELAY * 0.9 <= delay <= BASE_DELAY * 1.1