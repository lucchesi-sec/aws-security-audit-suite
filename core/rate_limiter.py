"""
Rate limiting for AWS API calls to prevent throttling.
"""

from typing import Dict, Optional
from asyncio_throttle import Throttler

# Global rate limiters for each service
_rate_limiters: Dict[str, Throttler] = {}

# Default rate limits (calls per second)
DEFAULT_RATE_LIMITS = {
    's3': 100,
    'ec2': 50,
    'iam': 20,
    'rds': 20,
    'lambda': 100,
    'sts': 10,
    'cloudtrail': 10,
    'config': 10,
    'default': 50
}


def get_rate_limiter(service: str, custom_limit: Optional[float] = None) -> Throttler:
    """Get or create a rate limiter for the specified service."""
    if service not in _rate_limiters:
        limit = custom_limit or DEFAULT_RATE_LIMITS.get(service, DEFAULT_RATE_LIMITS['default'])
        _rate_limiters[service] = Throttler(rate_limit=limit, period=1.0)
    
    return _rate_limiters[service]


async def rate_limited_call(service: str, coro, custom_limit: Optional[float] = None):
    """Execute a coroutine with rate limiting."""
    limiter = get_rate_limiter(service, custom_limit)
    async with limiter:
        return await coro
