use pyo3::types::PyBytes;
use pyo3::*;
use std::time::SystemTime;
use totp_rs::{Algorithm, Rfc6238, Secret, TOTP};
mod algorytm;
mod error;

pub use algorytm::Algorithm as PyAlgorithm;
pub use error::{
    PyRFC6238Error, PySecretError, PyTimeError, PyURLError, QRCodeError, RFC6238Error, SecretError,
    TOTPError, URLError,
};

#[pyclass(name = "TOTP")]
pub struct Totp {
    totp: TOTP,
}

/* create_* is mostly just handler related/helpful proxy methods */

fn create_secret() -> Result<Vec<u8>, PySecretError> {
    Ok(Secret::generate_secret().to_bytes()?)
}

fn create_totp(
    algorithm: Algorithm,
    digits: usize,
    skew: u8,
    step: u64,
    secret: Vec<u8>,
    issuer: Option<String>,
    account_name: String,
) -> Result<TOTP, PyURLError> {
    Ok(TOTP::new(
        algorithm,
        digits,
        skew,
        step,
        secret,
        issuer,
        account_name,
    )?)
}

fn create_rfc6238(
    digits: usize,
    secret: &[u8],
    issuer: Option<String>,
    account_name: Option<String>,
) -> Result<Rfc6238, PyRFC6238Error> {
    Ok(Rfc6238::new(
        digits,
        secret.to_vec(),
        issuer,
        account_name.unwrap_or_default(),
    )?)
}

fn create_from_rfc6238(rfc: Rfc6238) -> Result<TOTP, PyURLError> {
    Ok(TOTP::from_rfc6238(rfc)?)
}

fn create_from_rfc6238_with_defaults(secret: &[u8]) -> Result<Rfc6238, PyRFC6238Error> {
    Ok(Rfc6238::with_defaults(secret.to_vec())?)
}

fn create_from_url(url: String) -> Result<TOTP, PyURLError> {
    Ok(TOTP::from_url(url)?)
}
// Copied from the other library because it's not public.
fn system_time() -> Result<u64, PyTimeError> {
    let t = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(t)
}

#[pymethods]
impl Totp {
    #[new]
    #[pyo3(signature = (
        algorithm=PyAlgorithm::SHA1,
        digits=6,
        skew=1,
        step=30,
        secret=None,
        issuer=None,
        account_name=None,
    ))]
    pub fn new(
        algorithm: PyAlgorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: Option<&[u8]>,
        issuer: Option<String>,
        account_name: Option<String>,
    ) -> PyResult<Self> {
        let sec: Vec<u8> = match secret {
            None => create_secret()?,
            Some(s) => s.to_vec(),
        };
        let totp = create_totp(
            algorithm.into(),
            digits,
            skew,
            step,
            sec,
            issuer,
            account_name.unwrap_or_default(),
        )?;
        Ok(Self { totp })
    }

    #[staticmethod]
    #[pyo3(signature = (
        digits,
        secret,
        issuer=None,
        account_name=None,
    ))]
    pub fn from_rfc6238(
        digits: usize,
        secret: &[u8],
        issuer: Option<String>,
        account_name: Option<String>,
    ) -> PyResult<Self> {
        let totp = create_from_rfc6238(create_rfc6238(digits, secret, issuer, account_name)?)?;
        Ok(Self { totp })
    }

    #[staticmethod]
    pub fn from_rfc6238_with_defaults(secret: &[u8]) -> PyResult<Self> {
        let totp = create_from_rfc6238(create_from_rfc6238_with_defaults(secret)?)?;
        Ok(Self { totp })
    }

    #[pyo3(signature=(time=None))]
    pub fn sign<'a>(&self, time: Option<u64>, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        Ok(PyBytes::new(
            py,
            self.totp.sign(time.unwrap_or(system_time()?)).as_slice(),
        ))
    }

    #[pyo3(signature=(time=None))]
    pub fn generate(&self, time: Option<u64>) -> PyResult<String> {
        Ok(self.totp.generate(time.unwrap_or(system_time()?)))
    }
    /// faster than generate itself useful if there is no time option to take
    pub fn generate_currnet(&self) -> PyResult<String> {
        Ok(self.totp.generate(system_time()?))
    }

    /// checks to see if password is correct or not.
    #[pyo3(signature=(token, time=None))]
    pub fn check(&self, token: String, time: Option<u64>) -> PyResult<bool> {
        Ok(self.totp.check(&token, time.unwrap_or(system_time()?)))
    }

    /// checks to see if current password is correct or not.
    pub fn check_current(&self, token: String) -> PyResult<bool> {
        Ok(self.totp.check(&token, system_time()?))
    }

    pub fn get_secret_base32(&self) -> String {
        self.totp.get_secret_base32()
    }

    #[staticmethod]
    pub fn from_url(url: String) -> PyResult<Self> {
        Ok(Self {
            totp: create_from_url(url)?,
        })
    }

    pub fn get_url(&self) -> String {
        self.totp.get_url()
    }

    pub fn get_qr_base64(&self) -> PyResult<String> {
        match self.totp.get_qr_base64() {
            Ok(ret) => Ok(ret),
            Err(e) => Err(QRCodeError::new_err(e)),
        }
    }

    pub fn get_qr_png<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        match self.totp.get_qr_png() {
            Ok(ret) => Ok(PyBytes::new(py, ret.as_slice())),
            Err(e) => Err(QRCodeError::new_err(e)),
        }
    }

    // Getters
    #[getter]
    pub fn algorithm(&self) -> PyAlgorithm {
        match self.totp.algorithm {
            Algorithm::SHA1 => PyAlgorithm::SHA1,
            Algorithm::SHA256 => PyAlgorithm::SHA256,
            Algorithm::SHA512 => PyAlgorithm::SHA512,
        }
    }

    #[getter]
    pub fn digits(&self) -> usize {
        self.totp.digits
    }

    #[getter]
    pub fn skew(&self) -> u8 {
        self.totp.skew
    }

    #[getter]
    pub fn step(&self) -> u64 {
        self.totp.step
    }

    #[pyo3(signature=(time=None))]
    pub fn next_step(&self, time: Option<u64>) -> PyResult<u64> {
        Ok(self.totp.next_step(time.unwrap_or(system_time()?)))
    }

    pub fn next_step_current(&self) -> PyResult<u64> {
        Ok(self.totp.next_step(system_time()?))
    }

    pub fn ttl(&self) -> PyResult<u64> {
        let t = system_time()?;
        let step = self.totp.step;
        Ok(step - (t % step))
    }
}

// #[pyfunction]
// /// Formats the sum of two numbers as string
// fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
//     Ok((a + b).to_string())
// }

// This module is a python moudle implemented in Rust.

#[pymodule]
mod rust_totp {
    #[pymodule_export]
    use crate::algorytm::Algorithm;
    #[pymodule_export]
    use super::QRCodeError;
    #[pymodule_export]
    use super::RFC6238Error;
    #[pymodule_export]
    use super::SecretError;
    #[pymodule_export]
    use super::TOTPError;
    #[pymodule_export]
    use super::Totp;
    #[pymodule_export]
    use super::URLError;
    #[pymodule_export]
    use crate::error::TimeError;

    use crate::create_secret;
    use pyo3::pyfunction;
    use pyo3::types::PyBytes;
    use pyo3::{Bound, PyResult, Python};

    #[pyfunction]
    pub fn new_secret<'a>(py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        let secret = create_secret()?;
        Ok(PyBytes::new(py, secret.as_slice()))
    }
}
