class Life360Error(Exception):
    """Base class for Life360 exceptions"""


class CommError(Life360Error):
    """Life360 server communications error"""


class LoginError(Life360Error):
    """Invalid login username or password"""

class UnverifiedPhoneNumberError(LoginError):
    """Phone number not verified for login"""

class RequireOneTimePasscodeError(LoginError):
    """User requires OTP via SMS to login"""

class OneTimePasscodeError(LoginError):
    """Error occured while verifying OTP code."""
