import pytest

from rust_totp import TOTP, Algorithm, URLError

# Based off totp-rs's tests but for python.

def test_default_values() -> None:
    totp = TOTP()
    assert totp.algorithm == Algorithm.SHA1
    assert totp.digits == 6
    assert totp.skew == 1
    assert totp.step == 30


def test_wrong_issuer() -> None:
    with pytest.raises(
        URLError, match='Issuer can\'t contain a colon. "Github:" contains a colon'
    ):
        _ = TOTP(
            Algorithm.SHA1,
            6,
            1,
            1,
            b"TestSecretSuperSecret",
            "Github:",
            "constantoine@github.com",
        )


def test_wrong_account_name() -> None:
    with pytest.raises(
        URLError,
        match='Account Name can\'t contain a colon. "constantoine:github.com" contains a colon',
    ):
        _ = TOTP(
            Algorithm.SHA1,
            6,
            1,
            1,
            b"TestSecretSuperSecret",
            "Github",
            "constantoine:github.com",
        )



def test_url_for_secret_matches_sha1_without_issuer():
    totp = TOTP(
            Algorithm.SHA1,
            6,
            1,
            30,
            b"TestSecretSuperSecret",
            None,
            "constantoine@github.com",
        )
  
    url = totp.get_url()
    assert url == "otpauth://totp/constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"

def test_base32():
    totp = TOTP(Algorithm.SHA1, 6, 1, 1, b"TestSecretSuperSecret")
    assert totp.get_secret_base32() == "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"

def test_generate_token():
    totp = TOTP(Algorithm.SHA1, 6, 1, 1, b"TestSecretSuperSecret")
    assert totp.generate(1000) == "659761"
 