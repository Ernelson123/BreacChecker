import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

from breach_checker.models import PasswordResult, BreachResult, Breach


class Cache:
    """Cache local com TTL para resultados de verificação."""
    
    def __init__(self, cache_dir: Optional[Path] = None, ttl: int = 86400):
        self.ttl = ttl
        
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "breach-checker"
        
        self.cache_dir = cache_dir
        self.cache_file = self.cache_dir / "cache.json"
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cache_dir, 0o700)
        
        self._data = self._load()
    
    def _load(self) -> dict:
        if not self.cache_file.exists():
            return {}
        
        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)
            
            mode = os.stat(self.cache_file).st_mode & 0o777
            if mode != 0o600:
                os.chmod(self.cache_file, 0o600)
            
            return data
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save(self) -> None:
        try:
            temp_file = self.cache_file.with_suffix(".tmp")
            with open(temp_file, "w") as f:
                json.dump(self._data, f, indent=2)
            
            os.chmod(temp_file, 0o600)
            temp_file.replace(self.cache_file)
        except IOError:
            pass
    
    def _hash_key(self, key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()
    
    def get_password(self, password_hash: str) -> Optional[PasswordResult]:
        key = self._hash_key(f"pwd:{password_hash}")
        entry = self._data.get(key)
        
        if entry is None:
            return None
        
        if time.time() - entry["timestamp"] > self.ttl:
            del self._data[key]
            self._save()
            return None
        
        return PasswordResult(
            hash_prefix=entry["hash_prefix"],
            is_compromised=entry["is_compromised"],
            occurrence_count=entry["occurrence_count"],
        )
    
    def set_password(self, password_hash: str, result: PasswordResult) -> None:
        key = self._hash_key(f"pwd:{password_hash}")
        self._data[key] = {
            "hash_prefix": result.hash_prefix,
            "is_compromised": result.is_compromised,
            "occurrence_count": result.occurrence_count,
            "timestamp": time.time(),
        }
        self._save()
    
    def get_email(self, email_hash: str) -> Optional[BreachResult]:
        key = self._hash_key(f"email:{email_hash}")
        entry = self._data.get(key)
        
        if entry is None:
            return None
        
        if time.time() - entry["timestamp"] > self.ttl:
            del self._data[key]
            self._save()
            return None
        
        breaches = [
            Breach(
                name=b["name"],
                domain=b.get("domain", ""),
                breach_date=b.get("breach_date", ""),
                pwn_count=b.get("pwn_count", 0),
                description=b.get("description", ""),
                is_verified=b.get("is_verified", False),
                data_classes=b.get("data_classes", []),
            )
            for b in entry["breaches"]
        ]
        
        return BreachResult(email_hash=email_hash, breaches=breaches)
    
    def set_email(self, email_hash: str, result: BreachResult) -> None:
        key = self._hash_key(f"email:{email_hash}")
        self._data[key] = {
            "email_hash": result.email_hash,
            "breaches": [
                {
                    "name": b.name,
                    "domain": b.domain,
                    "breach_date": b.breach_date,
                    "pwn_count": b.pwn_count,
                    "description": b.description,
                    "is_verified": b.is_verified,
                    "data_classes": b.data_classes,
                }
                for b in result.breaches
            ],
            "timestamp": time.time(),
        }
        self._save()
    
    def clear(self) -> None:
        self._data = {}
        self._save()
    
    def cleanup_expired(self) -> int:
        initial_count = len(self._data)
        current_time = time.time()
        
        expired_keys = [
            key for key, entry in self._data.items()
            if current_time - entry["timestamp"] > self.ttl
        ]
        
        for key in expired_keys:
            del self._data[key]
        
        if len(self._data) != initial_count:
            self._save()
        
        return len(expired_keys)