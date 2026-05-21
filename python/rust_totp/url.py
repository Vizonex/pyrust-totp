"""
url
---

A Mini converter system for yarl urls and TOTP instances which
provides bridging between both aiohttp/yarl and rust-totp.

"""

from yarl import URL
from urllib.parse import unquote

from .rust_totp import TOTP, URLError, Algorithm

def totp_to_url(totp: TOTP) -> URL:
    """Converts a :class:`.TOTP` object to a :class:`.URL` object."""
    return URL(totp.get_url())

ALGORYTHMS = {
    "sha1": Algorithm.SHA1,
    "sha256": Algorithm.SHA256,
    "sha512": Algorithm.SHA512
}

def url_to_totp(url: URL | str) -> TOTP:
    """Converts a :class:`yarl.URL` or :class:`str` object to a :class:`.TOTP` object.
    
    :raises URLError: if url is somehow invalid in some way."""
    if isinstance(url, str):
        return TOTP.from_url(url)
    else:
        return TOTP.from_url(str(url))

        
        











