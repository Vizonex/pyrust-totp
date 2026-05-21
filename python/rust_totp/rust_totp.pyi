import sys
from enum import Enum, auto
from typing import final

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

class TOTPError(Exception):
    """Used for rasing TOTP related exceptions."""

    ...

class RFC6238Error(TOTPError):
    """Used for RFC6238 realted exceptions."""

    ...

class SecretError(TOTPError):
    """Raised when secret creation fails."""

    ...

class URLError(TOTPError):
    """Url Generation related exceptions."""

    ...

class TimeError(TOTPError):
    """
    Raised after having failed to get current system time.
    """

    ...

class QRCodeError(TOTPError):
    """Raised after failing to generate a QR Code."""

    ...

class Algorithm(Enum):
    SHA1 = auto()
    SHA256 = auto()
    SHA512 = auto()

@final
class TOTP:
    """2FA Instance for python. It uses a rust backend as extra security and implelemts
    sha1, sha256 and sha512. Know that if your goal is to subclass this object it's best 
    to write this object in as an attribute as there are some limitations within rust.
    """
    def __new__(
        cls,
        algorithm: Algorithm = Algorithm.SHA1,
        digits: int = 6,
        skew: int = 1,
        step: int = 30,
        secret: bytes | None = None,
        issuer: str | None = None,
        account_name: str | None = None,
    ) -> Self:
        """Creates a new TOTP instance.
        
        :param algorithm: the hmac algorythm to select, currently 
            sha1, sha256, and sha512 are supported hopefully the 
            hmac rust library will add support for more in the 
            future.

        :param digits: 
            the number of digits to use for each password.
        
        :param skew: 
            Number of steps allowed as network delay. 
            1 would mean 1 second. Allowing higher can be seen as being risky
            unless your working over the tor network for instance.

        :param step: Duration in seconds of each step.
            The recommended value per 
            [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) 
            is 30 seconds.

        :param secret: 
            A Non-Encoded value.

        :param issuer: 
            name of the service or website. 
            It's use is entirely optional.
        
        :param account_name:
            The name of the user's account. 
            It's use is entirely optional.
        """
        ...

    @staticmethod
    def from_rfc6238(
        digits: int,
        secret: bytes,
        issuer: str | None = None,
        account_name: str | None = None,
    ) -> "TOTP":
        """Creates a TOTP instance from an rfc6238 structure"""
        ...

    @staticmethod
    def from_rfc6238_with_defaults(secret: bytes) -> "TOTP":
        """Creates a TOTP instance using a secret."""
        ...

    def sign(self, time: int | None = None) -> bytes:
        """signs a given timestamp default will get the current system time.

        :raises TimeError: if obtaining the current system time fails.
        """
        ...

    def generate(self, time: int | None = None) -> str:
        """generates a password from a provided timestamp otherwise it uses the current system time.

        :raises TimeError: if obtaining the current system time fails."""
        ...

    def generate_current(self) -> str:
        """faster than :func:`.generate` as it knows to get the system's current time

        :raises TimeError: if obtaining the current system time fails."""
        ...

    def check(self, token: str, time: int | None = None) -> bool:
        """Checks to see if password is correct

        :raises TimeError: if obtaining the current system time fails.
        """
        ...

    def check_current(self, token: str) -> bool:
        """checks the current password based on the current system time

        :raises TimeError: if obtaining the current system time fails."""
        ...

    def get_secret_base32(self) -> str:
        """extracts current base32 key"""
        ...

    @staticmethod
    def from_url(url: str) -> "TOTP":
        """Generates TOTP instance from a given URL."""
        ...

    def get_url(self) -> str:
        """gets the TOTP URL."""
        ...

    def get_qr_base64(self) -> str:
        """
        Obtains the given QR Code as a base64 string.
        
        :raises QRCodeError: if qr code generation fails.
        """
        ...

    def get_qr_png(self) -> bytes:
        """
        Obtains the given QR Code as a png image in bytes.

        :raises QRCodeError: if qr code generation fails.
        """
        ...

    @property
    def algorithm(self) -> Algorithm:
        """The current hmac algorithm being used."""
        ...

    @property
    def digits(self) -> int:
        """Number of digits provided."""
        ...

    @property
    def step(self) -> int:
        """Number of Second intervals"""
        ...

    @property
    def skew(self) -> int:
        """The networking delay."""
        ...

    def next_step(self, time: int | None = None) -> int:
        """Returns the next timestamp.

        :raises TimeError: if obtaining the current system time fails."""
        ...

    def next_step_current(self) -> int:
        """returns the next timestamp using provided system time.

        :raises TimeError: if obtaining the current system time fails."""
        ...

    def ttl(self) -> int:
        """
        Obtains the time that is left until the next password

        :raises TimeError: if system time can't be obtained
        """
        ...

def new_secret() -> bytes:
    """Generates a new secret that creates a valid key."""
    ...
