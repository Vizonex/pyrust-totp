use pyo3::PyErr;
use pyo3::exceptions::PyException;
use std::time::SystemTimeError;
pub use totp_rs::Rfc6238Error;
pub use totp_rs::SecretParseError;
pub use totp_rs::TotpUrlError;

pyo3::create_exception!(
    rust_totp,
    TOTPError,
    PyException,
    "Used for rasing TOTP related exceptions."
);
pyo3::create_exception!(
    rust_totp,
    RFC6238Error,
    TOTPError,
    "Used for RFC6238 realted exceptions."
);
pyo3::create_exception!(
    rust_totp,
    SecretError,
    TOTPError,
    "Raised when secret creation fails."
);
pyo3::create_exception!(
    rust_totp,
    URLError,
    TOTPError,
    "Url Generation related exceptions."
);

// if it ever happens... (Probably not tested)

pyo3::create_exception!(
    rust_totp,
    TimeError,
    TOTPError,
    "Raised after having failed to get current system time."
);

pyo3::create_exception!(
    rust_totp,
    QRCodeError,
    TOTPError,
    "Raised after failing to generate a QR Code."
);

// === Proxies ===
pub struct PyTimeError(SystemTimeError);

impl From<SystemTimeError> for PyTimeError {
    fn from(value: SystemTimeError) -> Self {
        Self(value)
    }
}
impl From<PyTimeError> for PyErr {
    fn from(value: PyTimeError) -> Self {
        TimeError::new_err(value.0.to_string())
    }
}

pub struct PyRFC6238Error(Rfc6238Error);

impl From<PyRFC6238Error> for PyErr {
    fn from(error: PyRFC6238Error) -> Self {
        RFC6238Error::new_err(error.0.to_string())
    }
}

impl From<Rfc6238Error> for PyRFC6238Error {
    fn from(value: Rfc6238Error) -> Self {
        Self(value)
    }
}

pub struct PySecretError(SecretParseError);
impl From<PySecretError> for PyErr {
    fn from(error: PySecretError) -> Self {
        SecretError::new_err(error.0.to_string())
    }
}

impl From<SecretParseError> for PySecretError {
    fn from(value: SecretParseError) -> Self {
        Self(value)
    }
}

pub struct PyURLError(TotpUrlError);
impl From<PyURLError> for PyErr {
    fn from(error: PyURLError) -> Self {
        URLError::new_err(error.0.to_string())
    }
}
impl From<TotpUrlError> for PyURLError {
    fn from(value: TotpUrlError) -> Self {
        Self(value)
    }
}

// impl Into<PyErr> for Rfc6238Error {
//     fn into(self) -> PyErr {
//         RFC6238Error::new_err(self.to_string())
//     }
// }

// impl Into<PyErr> for SecretParseError {
//     fn into(self) -> PyErr {
//         SecretError::new_err(self.to_string())
//     }
// }

// impl Into<PyErr> for SecretParseError {
//     fn into(self) -> PyErr {
//         SecretError::new_err(self.to_string())
//     }
// }
