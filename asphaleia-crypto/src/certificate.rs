use pem::{encode, parse, Pem};
use rcgen::{Certificate as RcgenCertificate, CertificateParams, Error, KeyPair};

pub struct Certificate {
    cert: RcgenCertificate,
}

pub struct CertifiedKey {
    cert: Certificate,
    key_pair: KeyPair,
}

impl Certificate {
    pub fn new(params: CertificateParams, key_pair: &KeyPair) -> Result<Self, Error> {
        let cert = params.self_signed(key_pair)?;
        Ok(Self { cert })
    }

    pub fn from_pem(params_pem: &str, key_pem: &str) -> Result<Self, Error> {
        let params = CertificateParams::from_ca_cert_pem(params_pem)?;
        let key_pair = KeyPair::from_pem(key_pem)?;
        Self::new(params, &key_pair)
    }

    pub fn to_pem(&self) -> String {
        self.cert.pem()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }
}

impl CertifiedKey {
    pub fn new(name: &str) -> Result<Self, Error> {
        let mut params = CertificateParams::new(vec![name.to_string()])?;
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        let key_pair = KeyPair::generate()?;
        let cert = Certificate::new(params, &key_pair)?;
        Ok(Self { cert, key_pair })
    }

    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error> {
        let cert = Certificate::from_pem(cert_pem, key_pem)?;
        let key_pair = KeyPair::from_pem(key_pem)?;
        Ok(Self { cert, key_pair })
    }

    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }

    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_with_key() {
        let cert_with_key = CertifiedKey::new("test.example.com").unwrap();
        assert!(!cert_with_key.certificate().to_pem().is_empty());
        assert!(!cert_with_key.key_pair().serialize_pem().is_empty());
    }
}
