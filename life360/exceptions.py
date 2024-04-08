"""Life360 Exceptions."""
from .const import HTTP_Error


class Life360Error(Exception):
    """Base class for Life360 exceptions."""


class CommError(Life360Error):
    """Life360 server communications error."""

    def __init__(self, message: str, status: int | None) -> None:
        """Initialize exception."""
        super().__init__(message)
        self.status = status

    def __str__(self) -> str:
        """Return string."""
        return f"{super().__str__()}; status: {self.status}"


class LoginError(CommError):
    """Invalid login."""

    def __init__(self, message: str) -> None:
        """Initialize exception."""
        super().__init__(message, HTTP_Error.FORBIDDEN)


class NotFound(CommError):
    """Resource not found."""

    def __init__(self, message: str) -> None:
        """Initialize exception."""
        super().__init__(message, HTTP_Error.NOT_FOUND)


class RateLimited(CommError):
    """The server has rate-limited the request."""

    def __init__(self, message: str, retry_after: float | None) -> None:
        """Initialize exception."""
        super().__init__(message, HTTP_Error.TOO_MANY_REQUESTS)
        self.retry_after = retry_after

    def __str__(self) -> str:
        """Return string."""
        return f"{super().__str__()}; retry_after: {self.retry_after}"


class Unauthorized(CommError):
    """Unauthorized."""

    def __init__(self, message: str, authenticate: str | None) -> None:
        """Initialize exception."""
        super().__init__(message, HTTP_Error.UNAUTHORIZED)
        self.authenticate = authenticate

    def __str__(self) -> str:
        """Return string."""
        return f"{super().__str__()}; authenticate: {self.authenticate}"


class NotModified(Life360Error):
    """Resource not modified."""
