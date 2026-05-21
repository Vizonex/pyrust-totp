use pyo3::*;
use totp_rs::Algorithm as RustAlgorithm;

#[pyclass(from_py_object)]
#[derive(Debug, Clone)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Into<RustAlgorithm> for Algorithm {
    fn into(self) -> RustAlgorithm {
        match self {
            Algorithm::SHA1 => RustAlgorithm::SHA1,
            Algorithm::SHA256 => RustAlgorithm::SHA256,
            Algorithm::SHA512 => RustAlgorithm::SHA512,
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::SHA1
    }
}
