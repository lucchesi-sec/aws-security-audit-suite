"""
Async AWS client management for the security audit suite.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import aioboto3
from asyncio_throttle.throttler import Throttler

logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    """Configuration for AWS client connections."""

    region: str = "us-east-1"
    profile: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    max_retries: int = 3
    timeout: int = 30
    rate_limit: int = 10  # requests per second


class AsyncClientError(Exception):
    """Base exception for async client errors."""

    pass


class AsyncClientAuthError(AsyncClientError):
    """Authentication related errors."""

    pass


class AsyncClientRateLimitError(AsyncClientError):
    """Rate limiting errors."""

    pass


class AsyncClientManager:
    """Manages async AWS client connections with error handling."""

    def __init__(self, config: ClientConfig):
        self.config = config
        self._session = aioboto3.Session()
        self._clients: Dict[str, Any] = {}
        self._client_contexts: Dict[str, Any] = {}
        self._throttlers: Dict[str, Throttler] = {}
        self._retry_delays = [1, 2, 4, 8, 16]  # Exponential backoff delays

    async def get_client(self, service_name: str):
        """Get or create an async AWS client for the specified service."""
        if service_name not in self._clients:
            try:
                # Create async client context manager
                cm = self._session.client(
                    service_name,
                    region_name=self.config.region,
                    aws_access_key_id=self.config.access_key_id,
                    aws_secret_access_key=self.config.secret_access_key,
                    aws_session_token=self.config.session_token,
                )
                # Enter the async context to get the client instance
                client = await cm.__aenter__()
                self._client_contexts[service_name] = cm
                self._clients[service_name] = client

                # Create throttler for this service
                self._throttlers[service_name] = Throttler(
                    rate_limit=self.config.rate_limit, period=1
                )

                logger.debug(f"Created async client for {service_name}")
            except Exception as e:
                logger.error(
                    f"Failed to create client for {service_name}: {str(e)}"
                )
                raise AsyncClientAuthError(
                    f"Authentication failed for {service_name}: {str(e)}"
                )

        return self._clients[service_name]

    async def call_with_retry(
        self, service_name: str, method: str, *args, **kwargs
    ):
        """Call an AWS API method with retry logic and rate limiting."""
        client = await self.get_client(service_name)
        throttler = self._throttlers.get(service_name)

        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            try:
                # Apply rate limiting
                if throttler:
                    await throttler.acquire()

                # Call the method
                result = await getattr(client, method)(*args, **kwargs)
                logger.debug(
                    f"Successfully called {service_name}.{method} "
                    f"(attempt {attempt + 1})"
                )
                return result

            except client.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                error_message = e.response["Error"]["Message"]

                # Handle specific AWS error codes
                if error_code in [
                    "Throttling",
                    "ThrottlingException",
                    "RequestLimitExceeded",
                ]:
                    last_exception = AsyncClientRateLimitError(
                        f"AWS rate limit exceeded: {error_message}"
                    )
                    logger.warning(
                        f"Rate limit exceeded for {service_name}.{method}: "
                        f"{error_message}"
                    )
                elif error_code in [
                    "InvalidClientTokenId",
                    "SignatureDoesNotMatch",
                    "UnauthorizedOperation",
                ]:
                    raise AsyncClientAuthError(
                        f"Authentication failed: {error_message}"
                    )
                else:
                    # For other client errors, don't retry
                    logger.error(
                        f"AWS client error for {service_name}.{method}: "
                        f"{error_code} - {error_message}"
                    )
                    raise AsyncClientError(
                        f"AWS error: {error_code} - {error_message}"
                    )

            except Exception as e:
                last_exception = e
                logger.error(
                    f"Error calling {service_name}.{method}: {str(e)}"
                )

            # Retry with exponential backoff if not the last attempt
            if attempt < self.config.max_retries:
                delay = self._retry_delays[
                    min(attempt, len(self._retry_delays) - 1)
                ]
                logger.info(
                    f"Retrying {service_name}.{method} in {delay} seconds "
                    f"(attempt {attempt + 1})"
                )
                await asyncio.sleep(delay)

        # If we get here, all retries failed
        logger.error(f"All retries failed for {service_name}.{method}")
        raise last_exception or AsyncClientError(
            f"Failed to call {service_name}.{method} after "
            f"{self.config.max_retries} retries"
        )

    async def close(self):
        """Close all client connections."""
        for svc, cm in self._client_contexts.items():
            try:
                await cm.__aexit__(None, None, None)
            except Exception as e:
                logger.warning(f"Error closing client context for {svc}: {e}")

        self._clients.clear()
        self._client_contexts.clear()
        self._throttlers.clear()
        logger.debug("Closed all async clients")
