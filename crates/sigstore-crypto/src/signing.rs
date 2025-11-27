//! Key generation and signing using aws-lc-rs

use crate::error::{Error, Result};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair as AwsKeyPair, RsaKeyPair,
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
    },
};
use sigstore_types::{PemContent, SignatureBytes};

/// A PEM-encoded public key
///
/// This type wraps a public key in PEM format (with BEGIN/END headers).
/// It can be created from a `KeyPair` using `public_key_pem()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPem(String);

impl PublicKeyPem {
    /// Create a new PublicKeyPem from a PEM string
    ///
    /// Note: This does not validate the PEM format.
    pub fn new(pem: String) -> Self {
        Self(pem)
    }

    /// Get the PEM string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner PEM string
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for PublicKeyPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for PublicKeyPem {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<PublicKeyPem> for PemContent {
    fn from(pem: PublicKeyPem) -> Self {
        // PemContent stores the PEM text as bytes (base64-encoded when serialized)
        PemContent::from_bytes(pem.0.as_bytes())
    }
}

/// A cryptographic signature
///
/// This type wraps raw signature bytes. It can be created by signing
/// data with a `KeyPair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Create a new Signature from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create a new Signature from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the inner bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Get the length of the signature in bytes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the signature is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Signature> for SignatureBytes {
    fn from(sig: Signature) -> Self {
        SignatureBytes::new(sig.0)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Supported signing schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningScheme {
    /// ECDSA P-256 with SHA-256
    EcdsaP256Sha256,
    /// ECDSA P-256 with SHA-384 (non-standard but valid)
    EcdsaP256Sha384,
    /// ECDSA P-384 with SHA-384
    EcdsaP384Sha384,
    /// Ed25519
    Ed25519,
    /// RSA PSS with SHA-256
    RsaPssSha256,
    /// RSA PSS with SHA-384
    RsaPssSha384,
    /// RSA PSS with SHA-512
    RsaPssSha512,
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512
    RsaPkcs1Sha512,
}

impl SigningScheme {
    /// Get the name of this scheme
    pub fn name(&self) -> &'static str {
        match self {
            SigningScheme::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
            SigningScheme::EcdsaP256Sha384 => "ECDSA_P256_SHA384",
            SigningScheme::EcdsaP384Sha384 => "ECDSA_P384_SHA384",
            SigningScheme::Ed25519 => "ED25519",
            SigningScheme::RsaPssSha256 => "RSA_PSS_SHA256",
            SigningScheme::RsaPssSha384 => "RSA_PSS_SHA384",
            SigningScheme::RsaPssSha512 => "RSA_PSS_SHA512",
            SigningScheme::RsaPkcs1Sha256 => "RSA_PKCS1_SHA256",
            SigningScheme::RsaPkcs1Sha384 => "RSA_PKCS1_SHA384",
            SigningScheme::RsaPkcs1Sha512 => "RSA_PKCS1_SHA512",
        }
    }

    /// Check if this scheme uses SHA-256 for its signature hash.
    ///
    /// This is relevant for hashedrekord verification: Rekor always stores SHA-256
    /// hashes, so only schemes that use SHA-256 can be verified with prehashed
    /// verification when only the digest is available (not the original artifact).
    ///
    /// - Schemes using SHA-256: Can use `verify_signature_prehashed` with Rekor's hash
    /// - Schemes using SHA-384/512: Cannot use prehashed verification (hash mismatch)
    /// - Ed25519: Doesn't support prehashed mode
    pub fn uses_sha256(&self) -> bool {
        matches!(
            self,
            SigningScheme::EcdsaP256Sha256
                | SigningScheme::RsaPssSha256
                | SigningScheme::RsaPkcs1Sha256
        )
    }

    /// Check if this scheme supports prehashed verification.
    ///
    /// Ed25519 doesn't support prehashed verification (it signs the full message).
    /// ECDSA and RSA schemes support prehashed verification.
    pub fn supports_prehashed(&self) -> bool {
        !matches!(self, SigningScheme::Ed25519)
    }
}

/// A key pair for signing
pub enum KeyPair {
    /// ECDSA P-256 key pair
    EcdsaP256(EcdsaKeyPair),
    /// ECDSA P-384 key pair
    EcdsaP384(EcdsaKeyPair),
    /// Ed25519 key pair
    Ed25519(Ed25519KeyPair),
    /// RSA key pair
    Rsa(RsaKeyPair),
}

impl KeyPair {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate_ecdsa_p256() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string()))?;
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())?;
        Ok(KeyPair::EcdsaP256(key_pair))
    }

    /// Generate a new ECDSA P-384 key pair
    pub fn generate_ecdsa_p384() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-384 key".to_string()))?;
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref())?;
        Ok(KeyPair::EcdsaP384(key_pair))
    }

    /// Generate a new Ed25519 key pair
    pub fn generate_ed25519() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| Error::KeyGeneration("failed to generate Ed25519 key".to_string()))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())?;
        Ok(KeyPair::Ed25519(key_pair))
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        match self {
            KeyPair::EcdsaP256(kp) => kp.public_key().as_ref(),
            KeyPair::EcdsaP384(kp) => kp.public_key().as_ref(),
            KeyPair::Ed25519(kp) => kp.public_key().as_ref(),
            KeyPair::Rsa(kp) => kp.public_key().as_ref(),
        }
    }

    /// Sign data with this key pair
    pub fn sign(&self, data: &[u8]) -> Result<Signature> {
        let rng = SystemRandom::new();
        match self {
            KeyPair::EcdsaP256(kp) => {
                let sig = kp.sign(&rng, data)?;
                Ok(Signature::new(sig.as_ref().to_vec()))
            }
            KeyPair::EcdsaP384(kp) => {
                let sig = kp.sign(&rng, data)?;
                Ok(Signature::new(sig.as_ref().to_vec()))
            }
            KeyPair::Ed25519(kp) => {
                let sig = kp.sign(data);
                Ok(Signature::new(sig.as_ref().to_vec()))
            }
            KeyPair::Rsa(_) => Err(Error::Signing(
                "use sign_with_scheme for RSA keys".to_string(),
            )),
        }
    }

    /// Sign data with a specific scheme (required for RSA)
    pub fn sign_with_scheme(&self, data: &[u8], scheme: SigningScheme) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        match (self, scheme) {
            (KeyPair::EcdsaP256(kp), SigningScheme::EcdsaP256Sha256) => {
                let sig = kp.sign(&rng, data)?;
                Ok(sig.as_ref().to_vec())
            }
            (KeyPair::EcdsaP384(kp), SigningScheme::EcdsaP384Sha384) => {
                let sig = kp.sign(&rng, data)?;
                Ok(sig.as_ref().to_vec())
            }
            (KeyPair::Ed25519(kp), SigningScheme::Ed25519) => {
                let sig = kp.sign(data);
                Ok(sig.as_ref().to_vec())
            }
            (KeyPair::Rsa(kp), scheme) => {
                use aws_lc_rs::signature::{
                    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256,
                    RSA_PSS_SHA384, RSA_PSS_SHA512,
                };

                let mut sig = vec![0u8; kp.public_modulus_len()];

                match scheme {
                    SigningScheme::RsaPssSha256 => {
                        kp.sign(&RSA_PSS_SHA256, &rng, data, &mut sig)?;
                    }
                    SigningScheme::RsaPssSha384 => {
                        kp.sign(&RSA_PSS_SHA384, &rng, data, &mut sig)?;
                    }
                    SigningScheme::RsaPssSha512 => {
                        kp.sign(&RSA_PSS_SHA512, &rng, data, &mut sig)?;
                    }
                    SigningScheme::RsaPkcs1Sha256 => {
                        kp.sign(&RSA_PKCS1_SHA256, &rng, data, &mut sig)?;
                    }
                    SigningScheme::RsaPkcs1Sha384 => {
                        kp.sign(&RSA_PKCS1_SHA384, &rng, data, &mut sig)?;
                    }
                    SigningScheme::RsaPkcs1Sha512 => {
                        kp.sign(&RSA_PKCS1_SHA512, &rng, data, &mut sig)?;
                    }
                    _ => {
                        return Err(Error::UnsupportedAlgorithm(format!(
                            "RSA key cannot use scheme {:?}",
                            scheme
                        )));
                    }
                }
                Ok(sig)
            }
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "key type does not support scheme {:?}",
                scheme
            ))),
        }
    }

    /// Get the signing scheme for this key pair
    pub fn default_scheme(&self) -> SigningScheme {
        match self {
            KeyPair::EcdsaP256(_) => SigningScheme::EcdsaP256Sha256,
            KeyPair::EcdsaP384(_) => SigningScheme::EcdsaP384Sha384,
            KeyPair::Ed25519(_) => SigningScheme::Ed25519,
            KeyPair::Rsa(_) => SigningScheme::RsaPssSha256,
        }
    }

    /// Get the public key in DER-encoded SubjectPublicKeyInfo format
    pub fn public_key_to_der(&self) -> Result<Vec<u8>> {
        match self {
            KeyPair::EcdsaP256(kp) => {
                use der::asn1::BitString;
                use der::Encode;
                use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

                const ID_EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
                    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
                const SECP256R1: const_oid::ObjectIdentifier =
                    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

                let alg_id = AlgorithmIdentifier {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(
                        der::Any::encode_from(&SECP256R1).map_err(|e| Error::Der(e.to_string()))?,
                    ),
                };

                let pub_key_bytes = kp.public_key().as_ref();

                let spki = SubjectPublicKeyInfo {
                    algorithm: alg_id,
                    subject_public_key: BitString::from_bytes(pub_key_bytes)
                        .map_err(|e| Error::Der(e.to_string()))?,
                };

                spki.to_der().map_err(|e| Error::Der(e.to_string()))
            }
            _ => Err(Error::UnsupportedAlgorithm(
                "export to DER not implemented for this key type".to_string(),
            )),
        }
    }

    /// Get the public key in PEM-encoded SubjectPublicKeyInfo format
    pub fn public_key_to_pem(&self) -> Result<PublicKeyPem> {
        let der = self.public_key_to_der()?;
        let pem = pem::Pem::new("PUBLIC KEY", der);
        Ok(PublicKeyPem::new(pem::encode(&pem)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        assert!(!kp.public_key_bytes().is_empty());
    }

    #[test]
    fn test_generate_ecdsa_p384() {
        let kp = KeyPair::generate_ecdsa_p384().unwrap();
        assert!(!kp.public_key_bytes().is_empty());
    }

    #[test]
    fn test_generate_ed25519() {
        let kp = KeyPair::generate_ed25519().unwrap();
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_sign_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data to sign";
        let sig = kp.sign(data).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_sign_ed25519() {
        let kp = KeyPair::generate_ed25519().unwrap();
        let data = b"test data to sign";
        let sig = kp.sign(data).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_ecdsa_p256_public_key_len() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let bytes = kp.public_key_bytes();
        println!("Public key len: {}", bytes.len());
        // Uncompressed P-256 key should be 65 bytes (0x04 + 32 bytes X + 32 bytes Y)
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
    }
}
