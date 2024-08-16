use pem::{encode, parse, Pem};
use rcgen::{Certificate as RcgenCertificate, CertificateParams, Error as RcgenError, KeyPair};
use std::fs;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Could not parse certificate")]
    CouldNotParseCertificate,
    #[error("Could not parse certificate signing request")]
    CouldNotParseCertificationRequest,
    #[error("Could not parse key pair")]
    CouldNotParseKeyPair,
    #[error("Invalid ASN.1 string: {0}")]
    InvalidAsn1String(String),
    #[error("Invalid IP address octet length of {0} bytes")]
    InvalidIpAddressOctetLength(usize),
    #[error("There is no support for generating keys for the given algorithm")]
    KeyGenerationUnavailable,
    #[error("The requested signature algorithm is not supported")]
    UnsupportedSignatureAlgorithm,
    #[error("Unspecified ring error")]
    RingUnspecified,
    #[error("Key rejected by ring: {0}")]
    RingKeyRejected(String),
    #[error("Time error")]
    Time,
    #[error("Remote key error")]
    RemoteKeyError,
    #[error("Certificate parameter unsupported in CSR")]
    UnsupportedInCsr,
    #[error("Invalid CRL next update parameter")]
    InvalidCrlNextUpdate,
    #[error("CRL issuer must specify no key usage, or key usage including cRLSign")]
    IssuerNotCrlSigner,
    #[error("A serial number must be specified")]
    MissingSerialNumber,
    #[error("Rcgen error: {0}")]
    RcgenError(#[from] RcgenError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("PEM error: {0}")]
    PemError(#[from] pem::PemError),
}

pub struct Certificate {
    cert: RcgenCertificate,
    key_pair: KeyPair,
}

impl Certificate {
    pub fn new(name: &str) -> Result<Self, CertificateError> {
        if name.is_empty() {
            return Err(CertificateError::InvalidAsn1String(
                "Empty name".to_string(),
            ));
        }
        let params = CertificateParams::new(vec![name.to_string()])?;
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        Ok(Self { cert, key_pair })
    }

    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    pub fn key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    pub fn save(&self, cert_path: &str, key_path: &str) -> Result<(), CertificateError> {
        let cert_pem = Pem::new("CERTIFICATE", self.cert_pem().into_bytes());
        let key_pem = Pem::new("PRIVATE KEY", self.key_pem().into_bytes());

        fs::write(cert_path, encode(&cert_pem))?;
        fs::write(key_path, encode(&key_pem))?;
        Ok(())
    }

    pub fn load(cert_path: &str, key_path: &str) -> Result<Self, CertificateError> {
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;

        let cert_pem = parse(&cert_pem)?;
        let key_pem = parse(&key_pem)?;

        let key_pair = KeyPair::from_pem(std::str::from_utf8(key_pem.contents())?)?;
        let params =
            CertificateParams::from_ca_cert_pem(std::str::from_utf8(cert_pem.contents())?)?;
        let cert = params.self_signed(&key_pair)?;
        Ok(Self { cert, key_pair })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_save_and_load_certificate() {
        let temp_dir = tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let cert = Certificate::new("test.example.com").unwrap();
        cert.save(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
            .unwrap();

        assert!(cert_path.exists());
        assert!(key_path.exists());

        let loaded_cert =
            Certificate::load(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();

        assert_eq!(
            cert.cert.params().distinguished_name,
            loaded_cert.cert.params().distinguished_name
        );
        assert_eq!(
            cert.cert.params().subject_alt_names,
            loaded_cert.cert.params().subject_alt_names
        );
        assert_eq!(
            cert.cert.params().key_usages,
            loaded_cert.cert.params().key_usages
        );

        assert_eq!(
            cert.key_pair.public_key_raw(),
            loaded_cert.key_pair.public_key_raw()
        );
    }

    #[test]
    fn test_invalid_certificate() {
        let result = Certificate::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent_files() {
        let result = Certificate::load("nonexistent_cert.pem", "nonexistent_key.pem");
        assert!(result.is_err());
    }
}
