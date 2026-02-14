"""
Smart caching module for security scan results.
Caches findings based on content hash to avoid re-scanning unchanged files.
"""

import hashlib
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from claudecode.schema import SecurityFinding


class CacheManager:
    """Manages caching of security scan results."""

    CACHE_VERSION = "v2.0"
    DEFAULT_TTL_DAYS = 7

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        prompt_version: str = "1.0",
        ttl_days: int = DEFAULT_TTL_DAYS,
        enabled: bool = True,
    ) -> None:
        """
        Initialize cache manager.

        Args:
            cache_dir: Directory for cache storage (defaults to GitHub Actions cache or .security_cache)
            prompt_version: Version identifier for prompt templates
            ttl_days: Time-to-live for cache entries in days
            enabled: Whether caching is enabled
        """
        self.enabled = enabled
        self.prompt_version = prompt_version
        self.ttl_days = ttl_days

        if not enabled:
            self.cache_dir = None
            return

        # Use GitHub Actions cache if available, otherwise local directory
        github_cache = os.environ.get("GITHUB_CACHE_PATH")
        if github_cache:
            self.cache_dir = Path(github_cache) / "security_scan"
        elif cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path(".security_cache")

        # Create cache directory if it doesn't exist
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Clean expired entries on initialization
        self._clean_expired_entries()

    def get_cache_key(self, file_content: str) -> str:
        """
        Generate cache key from file content and prompt version.

        Args:
            file_content: Content of the file

        Returns:
            Cache key as hex string
        """
        # Include prompt version in cache key so changes to prompts invalidate cache
        content = f"{self.CACHE_VERSION}:{self.prompt_version}:{file_content}"
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, file_path: str, file_content: str) -> Optional[List[SecurityFinding]]:
        """
        Retrieve cached findings for a file.

        Args:
            file_path: Path to the file
            file_content: Current content of the file

        Returns:
            List of cached findings if available and valid, None otherwise
        """
        if not self.enabled or not self.cache_dir:
            return None

        cache_key = self.get_cache_key(file_content)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)

            # Validate cache entry
            if not self._is_valid_cache_entry(cached_data):
                # Invalid or expired, remove it
                cache_file.unlink()
                return None

            # Deserialize findings
            findings = [SecurityFinding(**finding) for finding in cached_data["findings"]]
            return findings

        except (json.JSONDecodeError, KeyError, TypeError):
            # Corrupted cache file, remove it
            if cache_file.exists():
                cache_file.unlink()
            return None

    def set(
        self, file_path: str, file_content: str, findings: List[SecurityFinding]
    ) -> None:
        """
        Cache findings for a file.

        Args:
            file_path: Path to the file
            file_content: Content of the file
            findings: Security findings to cache
        """
        if not self.enabled or not self.cache_dir:
            return

        cache_key = self.get_cache_key(file_content)
        cache_file = self.cache_dir / f"{cache_key}.json"

        cache_entry = {
            "version": self.CACHE_VERSION,
            "prompt_version": self.prompt_version,
            "file_path": file_path,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "ttl_days": self.ttl_days,
            "findings": [finding.to_dict() for finding in findings],
        }

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2)
        except Exception:
            # If we can't write to cache, that's okay, just continue
            pass

    def invalidate(self, file_path: str, file_content: str) -> None:
        """
        Invalidate cache entry for a file.

        Args:
            file_path: Path to the file
            file_content: Content of the file
        """
        if not self.enabled or not self.cache_dir:
            return

        cache_key = self.get_cache_key(file_content)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if cache_file.exists():
            cache_file.unlink()

    def clear(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of cache entries removed
        """
        if not self.enabled or not self.cache_dir:
            return 0

        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1

        return count

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        if not self.enabled or not self.cache_dir:
            return {
                "enabled": False,
                "total_entries": 0,
                "valid_entries": 0,
                "expired_entries": 0,
                "cache_size_mb": 0,
            }

        total = 0
        valid = 0
        expired = 0
        total_size = 0

        for cache_file in self.cache_dir.glob("*.json"):
            total += 1
            total_size += cache_file.stat().st_size

            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)

                if self._is_valid_cache_entry(cached_data):
                    valid += 1
                else:
                    expired += 1
            except Exception:
                expired += 1

        return {
            "enabled": True,
            "cache_dir": str(self.cache_dir),
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": expired,
            "cache_size_mb": round(total_size / (1024 * 1024), 2),
        }

    def _is_valid_cache_entry(self, cached_data: Dict[str, Any]) -> bool:
        """
        Check if a cache entry is valid and not expired.

        Args:
            cached_data: Cached data dictionary

        Returns:
            True if valid, False otherwise
        """
        # Check version
        if cached_data.get("version") != self.CACHE_VERSION:
            return False

        # Check prompt version
        if cached_data.get("prompt_version") != self.prompt_version:
            return False

        # Check TTL
        timestamp_str = cached_data.get("timestamp")
        if not timestamp_str:
            return False

        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            age = datetime.utcnow() - timestamp.replace(tzinfo=None)

            ttl = cached_data.get("ttl_days", self.ttl_days)
            if age > timedelta(days=ttl):
                return False
        except (ValueError, TypeError):
            return False

        return True

    def _clean_expired_entries(self) -> None:
        """Remove expired cache entries."""
        if not self.enabled or not self.cache_dir:
            return

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)

                if not self._is_valid_cache_entry(cached_data):
                    cache_file.unlink()
            except Exception:
                # Corrupted file, remove it
                cache_file.unlink()
