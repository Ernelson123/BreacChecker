import os
import pytest
import time
from pathlib import Path
from breach_checker.cache import Cache
from breach_checker.models import PasswordResult, BreachResult, Breach


class TestCache:
    @pytest.fixture
    def cache(self, tmp_path):
        return Cache(cache_dir=tmp_path, ttl=1)
    
    def test_cache_password(self, cache):
        result = PasswordResult(hash_prefix="5BAA6", is_compromised=True, occurrence_count=100)
        cache.set_password("test_hash", result)
        retrieved = cache.get_password("test_hash")
        assert retrieved is not None
        assert retrieved.hash_prefix == "5BAA6"
    
    def test_cache_ttl_expires(self, cache):
        result = PasswordResult(hash_prefix="5BAA6", is_compromised=True, occurrence_count=100)
        cache.set_password("test_hash", result)
        assert cache.get_password("test_hash") is not None
        time.sleep(1.1)
        assert cache.get_password("test_hash") is None
    
    def test_cache_file_permissions(self, tmp_path):
        cache = Cache(cache_dir=tmp_path)
        result = PasswordResult(hash_prefix="5BAA6", is_compromised=True, occurrence_count=100)
        cache.set_password("test_hash", result)
        mode = os.stat(cache.cache_file).st_mode & 0o777
        assert mode == 0o600