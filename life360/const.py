"""Life360 Constants."""
from __future__ import annotations

from enum import IntEnum

HOST = "api-cloudfront.life360.com"
USER_AGENT = "com.life360.android.safetymapd/KOKO/23.50.0 android/13"
CLIENT_TOKEN = (
    "Y2F0aGFwYWNyQVBoZUtVc3RlOGV2ZXZldnVjSGFmZVRydVl1Zn"
    "JhYzpkOEM5ZVlVdkE2dUZ1YnJ1SmVnZXRyZVZ1dFJlQ1JVWQ=="
)


class HTTP_Error(IntEnum):
    """HTTP Error Codes."""

    NOT_MODIFIED = 304
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    TOO_MANY_REQUESTS = 429
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIME_OUT = 504
    SERVER_UNKNOWN_ERROR = 520
