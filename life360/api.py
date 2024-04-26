"""Life360 API."""
from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping, MutableMapping
from contextlib import suppress
from json import JSONDecodeError
import logging
import re
import traceback
from typing import Any, cast

from aiohttp import (
    ClientConnectionError,
    ClientError,
    ClientResponse,
    ClientResponseError,
    ClientSession,
)
from aiohttp.typedefs import LooseHeaders

from .const import CLIENT_TOKEN, HOST, USER_AGENT, HTTP_Error
from .exceptions import (
    CommError,
    Life360Error,
    LoginError,
    NotFound,
    NotModified,
    RateLimited,
    Unauthorized,
)

_LOGGER = logging.getLogger(__name__)

_PROTOCOL = "https://"
_BASE_URL = f"{_PROTOCOL}{HOST}"
_BASE_CMD_FMT = f"{_BASE_URL}/v{{}}/"
_TOKEN_URL = f"{_BASE_CMD_FMT.format(3)}oauth2/token"
_CIRCLES_URL = f"{_BASE_CMD_FMT.format(4)}circles"
_CIRCLE_URL_FMT = f"{_BASE_CMD_FMT.format(3)}circles/{{cid}}"
_CIRCLE_MEMBERS_URL_FMT = f"{_CIRCLE_URL_FMT}/members"
_MEMBER_URL_FMT = f"{_CIRCLE_MEMBERS_URL_FMT}/{{mid}}"

_HEADERS = {
    "accept": "application/json",
    "cache-control": "no-cache",
    "user-agent": USER_AGENT,
}

_RETRY_EXCEPTIONS = (ClientConnectionError, asyncio.TimeoutError)
_RETRY_CLIENT_RESPONSE_ERRORS = (
    HTTP_Error.BAD_GATEWAY,
    HTTP_Error.SERVICE_UNAVAILABLE,
    HTTP_Error.GATEWAY_TIME_OUT,
    HTTP_Error.SERVER_UNKNOWN_ERROR,
)

_URL_REDACTIONS = (re.compile(r"/(?:(?:circles)|(?:members))/(?!REDACTED)([\w-]+)"),)
_RESP_REPR_REDACTIONS = (
    *_URL_REDACTIONS,
    re.compile(r"'Bearer (?!REDACTED')([^']+)'"),
    re.compile(r"'Set-Cookie': '[^=]+=(?!REDACTED[;'])([^;']+)[;']"),
)
_EXC_REPR_REDACTIONS = (
    *_RESP_REPR_REDACTIONS,
    re.compile(r"'Cookie': '[^=]+=(?!REDACTED[;'])([^;']+)(?:; [^=]+=([^;']+))*'"),
)
_RESP_TEXT_BASIC_REDACTIONS = (
    re.compile(r'"(?:(?:id)|(?:sourceId)|(?:avatar))":"(?!REDACTED")([^"]+)"'),
)
_RESP_TEXT_ALL_REDACTIONS = (
    *_RESP_TEXT_BASIC_REDACTIONS,
    re.compile(
        r'"(?:'
        r"(?:value)|(?:login(?:(?:Phone)|(?:Email)))"
        r"|(?:latitude)|(?:longitude)|(?:address\d)|(?:shortAddress)"
        r')":"(?!REDACTED")([^"]+)"'
    ),
)


def _retry(exc: Exception) -> bool:
    """Determine if request should be retried."""
    if isinstance(exc, _RETRY_EXCEPTIONS):
        return True
    return (
        isinstance(exc, ClientResponseError)
        and exc.status in _RETRY_CLIENT_RESPONSE_ERRORS
    )


def _format_exc(exc: Exception) -> str:
    """Format an exception."""
    return "; ".join(s.strip() for s in traceback.format_exception_only(exc))


class NameAdapter(logging.LoggerAdapter):
    """Logging adapter to add name prefix."""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        """Add name prefix."""
        return f"{cast(Mapping[str, object], self.extra)['name']}: {msg}", kwargs


class Life360:
    """Life360 API."""

    _logger: logging.Logger | logging.LoggerAdapter

    def __init__(
        self,
        session: ClientSession,
        max_retries: int,
        authorization: str | None = None,
        *,
        name: str | None = None,
        verbosity: int = 0,
    ) -> None:
        """Initialize API.

        name: Prefix for log messages, not affected by verbosity.

        verbosity:
        0 -> Minimal DEBUG messages with redactions
        1 -> Add client response headers
        2 -> Add client response text/json
        3 -> No informational redactions
        4 -> No redactions
        """
        self._session = session
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self._max_attempts = max_retries + 1
        self.authorization = authorization
        if name:
            self._logger = NameAdapter(_LOGGER, {"name": name})
        else:
            self._logger = _LOGGER
        self.verbosity = verbosity
        self._etags: dict[str, str] = {}

    @property
    def verbosity(self) -> int:
        """Return verbosity level."""
        return self._verbosity

    @verbosity.setter
    def verbosity(self, value: int) -> None:
        """Set verbosity level."""
        if not (0 <= value <= 4):
            raise ValueError("verbosity must be between 0 and 4, inclusive")
        self._verbosity = value

    async def login_by_username(self, username: str, password: str) -> str:
        """Log into Life360 server using username & password."""
        reply = cast(
            Mapping[str, str],
            await self._request(
                _TOKEN_URL,
                method="post",
                raise_not_modified=False,
                data={
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                },
                authorization=f"Basic {CLIENT_TOKEN}",
            ),
        )
        try:
            self.authorization = f"{reply['token_type']} {reply['access_token']}"
        except KeyError:
            raise Life360Error(
                f"Unexpected response while logging in by username: {reply}"
            ) from None
        return self.authorization

    async def get_circles(
        self, *, raise_not_modified: bool = False
    ) -> list[dict[str, str]]:
        """Get basic data about all Circles."""
        return cast(
            dict[str, list[dict[str, str]]],
            await self._request(_CIRCLES_URL, raise_not_modified),
        )["circles"]

    async def get_circle_members(
        self, cid: str, *, raise_not_modified: bool = False
    ) -> list[dict[str, Any]]:
        """Get details for Members in given Circle."""
        return cast(
            dict[str, list[dict[str, Any]]],
            await self._request(
                _CIRCLE_MEMBERS_URL_FMT.format(cid=cid), raise_not_modified
            ),
        )["members"]

    async def get_circle_member(
        self, cid: str, mid: str, *, raise_not_modified: bool = False
    ) -> dict[str, Any]:
        """Get details for Member as seen from given Circle."""
        return cast(
            dict[str, Any],
            await self._request(
                _MEMBER_URL_FMT.format(cid=cid, mid=mid), raise_not_modified
            ),
        )

    async def _request(
        self,
        url: str,
        /,
        raise_not_modified: bool,
        method: str = "get",
        *,
        authorization: str | None = None,
        **kwargs: dict[str, Any],
    ) -> Any:
        """Make a request to server."""
        if authorization is None:
            authorization = self.authorization
        if authorization is None:
            raise LoginError("Must login")

        headers = _HEADERS
        if authorization != "":
            headers["authorization"] = authorization
        if raise_not_modified and (etag := self._etags.get(url)):
            headers["if-none-match"] = etag
        kwargs.setdefault("headers", {}).update(headers)

        for attempt in range(1, self._max_attempts + 1):
            resp: ClientResponse | None = None
            status: int | None = None
            try:
                resp = cast(
                    ClientResponse,
                    await getattr(self._session, method)(url, **kwargs),
                )
                status = resp.status
                resp.raise_for_status()
            except ClientError as exc:
                self._logger.debug(
                    "Request error: %s(%s), attempt %i: %s",
                    method.upper(),
                    self._redact(url, _URL_REDACTIONS),
                    attempt,
                    self._redact(repr(exc), _EXC_REPR_REDACTIONS),
                )
                await self._dump_resp_text(resp)
                if _retry(exc) and attempt < self._max_attempts:
                    continue
                # Try to return a useful error message.
                try:
                    err_msg = cast(
                        Mapping[str, str],
                        await cast(ClientResponse, resp).json(),
                    )["errorMessage"].lower()
                except (AttributeError, ClientError, KeyError, JSONDecodeError):
                    err_msg = self._redact(_format_exc(exc), _URL_REDACTIONS)
                match status:
                    case HTTP_Error.UNAUTHORIZED:
                        authenticate = None
                        with suppress(KeyError):
                            authenticate = cast(
                                LooseHeaders, cast(ClientResponseError, exc).headers
                            )["www-authenticate"]
                        raise Unauthorized(err_msg, authenticate) from exc
                    case HTTP_Error.FORBIDDEN:
                        raise LoginError(err_msg) from exc
                    case HTTP_Error.NOT_FOUND:
                        raise NotFound(err_msg) from exc
                    case HTTP_Error.TOO_MANY_REQUESTS:
                        try:
                            retry_after = float(
                                cast(
                                    LooseHeaders, cast(ClientResponseError, exc).headers
                                )["retry-after"]
                            )
                        except (KeyError, TypeError):
                            retry_after = None
                        raise RateLimited(err_msg, retry_after) from exc
                    case _:
                        raise CommError(err_msg, status) from exc

            await self._dump_resp(resp)
            if status == HTTP_Error.NOT_MODIFIED:
                raise NotModified
            if etag := resp.headers.get("l360-etag"):
                self._etags[url] = etag
            try:
                return await resp.json()
            except (ClientError, JSONDecodeError) as exc:
                try:
                    resp_ = await resp.text()
                except ClientError:
                    resp_ = str(resp)
                self._logger.debug(
                    "While parsing response: %r: %s",
                    resp_,
                    self._redact(repr(exc), _EXC_REPR_REDACTIONS),
                )
                raise Life360Error(
                    self._redact(_format_exc(exc), _URL_REDACTIONS)
                ) from None

    async def _dump_resp_text(self, resp: ClientResponse | None) -> None:
        """Dump response text to log."""
        if resp is None or self.verbosity < 2:
            return
        try:
            if not (text := await resp.text()):
                return
        except ClientError:
            return
        self._logger.debug(
            "Response data: %s",
            self._redact(
                text,
                _RESP_TEXT_ALL_REDACTIONS
                if self.verbosity < 3
                else _RESP_TEXT_BASIC_REDACTIONS,
            ),
        )

    async def _dump_resp(self, resp: ClientResponse) -> None:
        """Dump response to log."""
        if self.verbosity < 1:
            return
        resp_repr = repr(resp).replace("\n", " ")
        self._logger.debug("Response headers: %s", self._redact(resp_repr, _RESP_REPR_REDACTIONS))
        await self._dump_resp_text(resp)

    def _redact(self, string: str, redactions: Iterable[re.Pattern]) -> str:
        """Redact string for lower verbosity levels."""
        if self.verbosity >= 4:
            return string
        for redaction in redactions:
            while m := redaction.search(string):
                for i in range(m.lastindex, 0, -1):  # type: ignore[arg-type]
                    string = "REDACTED".join([string[: m.start(i)], string[m.end(i) :]])
        return string
