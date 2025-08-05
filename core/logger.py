"""Central logging utilities for AWS Security Audit Suite.

Provides a thin wrapper around structlog so that modules can obtain a
JSON-capable logger without taking a mandatory dependency on structlog at
runtime. If structlog is unavailable or mis-configured, the standard
library ``logging`` module is used transparently.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

try:
    import structlog
except ModuleNotFoundError:  # pragma: no cover – optional dependency
    structlog = None  # type: ignore[assignment]


def get_logger(
    name: Optional[str] = None, **kwargs: Any
) -> logging.Logger:  # noqa: ANN401
    """Return a configured logger.

    If *structlog* is available use :pyfunc:`structlog.get_logger` so that all
    logs are emitted in a structured (JSON) format; otherwise fall back to
    :pyfunc:`logging.getLogger`.
    """
    if structlog is not None:  # pragma: no cover
        return structlog.get_logger(name, **kwargs)

    return logging.getLogger(name)
