"""Python package for accessing Life360 REST API."""

from .api import Life360
from .exceptions import (
    CommError,
    Life360Error,
    LoginError,
    NotFound,
    NotModified,
    RateLimited,
    Unauthorized,
)
from .version import __version__

__all__ = [
    # api
    "Life360",
    # exceptions
    "Life360Error",
    # exceptions Life360Error's
    "CommError",
    "NotModified",
    # exceptions CommError's
    "LoginError",
    "NotFound",
    "RateLimited",
    "Unauthorized",
    # version
    "__version__",
]
