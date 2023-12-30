"""Test function."""

import logging
import asyncio

from life360 import Life360

_LOGGER = logging.getLogger(__name__)

async def main():
    controller = Life360()
    user = await controller.user_lookup(email=input("Enter email address: "))
    if user.get("loginMethod", "phone") == "phone":
        _LOGGER.info("This user requires SMS based OTP to login.")
        await controller.send_sms_otp(
            country_code=input("Enter country code of mobile number (without leading '+'): "),
            national_number=input("Enter phone number: ")
        )
        _LOGGER.info("SMS OTP sent.")
        await controller.verify_sms_otp(
            verification_code=input("Enter verification code: ")
        )
    else:
        _LOGGER.info("This user requires password authentication.")
        await controller.get_authorization(
            username=input("Enter email address: "),
            password=input("Enter password: ")
        )
    _LOGGER.info("Auth completed.")
    circles = await controller.get_circles()
    _LOGGER.info(circles)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
