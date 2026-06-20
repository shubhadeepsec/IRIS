from abc import ABC, abstractmethod
from typing import Any, Optional
import aiohttp

class BaseCollector(ABC):
    """Base class for all collectors."""
    
    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp ClientSession."""
        if not self._session or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _fetch(self, url: str, headers: dict = None) -> Any:
        """Async HTTP JSON request."""
        session = await self.get_session()
        try:
            async with session.get(url, headers=headers, timeout=10) as resp:
                return await resp.json() if resp.status == 200 else None
        except Exception:
            return None

    async def _fetch_text(self, url: str, headers: dict = None) -> Optional[str]:
        """Async HTTP text request."""
        session = await self.get_session()
        try:
            async with session.get(url, headers=headers, timeout=10) as resp:
                return await resp.text() if resp.status == 200 else None
        except Exception:
            return None

    async def close(self) -> None:
        """Close the active ClientSession."""
        if self._session and not self._session.closed:
            await self._session.close()

    @abstractmethod
    async def collect(self, target: str) -> dict:
        """Gather intelligence on target."""
        pass
    
    @abstractmethod
    def parse(self, raw: dict) -> dict:
        """Normalize raw data."""
        pass
