//! Signature verification using aws-lc-rs

use crate::error::{Error, Result};
use crate::signing::SigningScheme;
use aws_lc_rs::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1, ECDSA_P384_SHA384_ASN1, ED25519,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
};

/// A public key for verification
pub struct VerificationKey {
    /// Raw public key bytes
    pub bytes: Vec<u8>,
    /// The scheme to use for verification
    pub scheme: SigningScheme,
}

impl VerificationKey {
    /// Create a new verification key
    pub fn new(bytes: Vec<u8>, scheme: SigningScheme) -> Self {
        Self { bytes, scheme }
    }

    /// Verify a signature over data
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        match self.scheme {
            SigningScheme::EcdsaP256Sha256 => {
                let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ECDSA P-256 SHA-256 signature invalid".to_string()))
            }
            SigningScheme::EcdsaP256Sha384 => {
                let key = UnparsedPublicKey::new(&ECDSA_P256_SHA384_ASN1, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ECDSA P-256 SHA-384 signature invalid".to_string()))
            }
            SigningScheme::EcdsaP384Sha384 => {
                let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ECDSA P-384 SHA-384 signature invalid".to_string()))
            }
            SigningScheme::Ed25519 => {
                let key = UnparsedPublicKey::new(&ED25519, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("Ed25519 signature invalid".to_string()))
            }
            SigningScheme::RsaPssSha256 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPssSha384 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPssSha512 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-512 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha256 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha384 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha512 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-512 signature invalid".to_string())
                })
            }
        }
    }
}

/// Verify a signature using the specified scheme
pub fn verify_signature(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
    scheme: SigningScheme,
) -> Result<()> {
    let key = VerificationKey::new(public_key.to_vec(), scheme);
    key.verify(data, signature)
}

/// Verify a signature over prehashed data using the specified scheme
///
/// This is used for hashedrekord verification where the signature is over
/// the SHA-256 hash of the artifact, not the artifact itself.
pub fn verify_signature_prehashed(
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
    scheme: SigningScheme,
) -> Result<()> {
    use aws_lc_rs::signature::{
        UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED,
    };

    match scheme {
        SigningScheme::EcdsaP256Sha256 => {
            // For prehashed ECDSA, we need to use the FIXED variant which doesn't hash
            // The digest should be 32 bytes (SHA-256)
            if digest.len() != 32 {
                return Err(Error::Verification(format!(
                    "ECDSA P-256 prehashed verification requires 32-byte digest, got {}",
                    digest.len()
                )));
            }
            let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key);
            key.verify(digest, signature)
                .map_err(|_| Error::Verification("ECDSA P-256 signature invalid".to_string()))
        }
        SigningScheme::EcdsaP384Sha384 => {
            // For prehashed ECDSA P-384, digest should be 48 bytes (SHA-384)
            if digest.len() != 48 {
                return Err(Error::Verification(format!(
                    "ECDSA P-384 prehashed verification requires 48-byte digest, got {}",
                    digest.len()
                )));
            }
            let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, public_key);
            key.verify(digest, signature)
                .map_err(|_| Error::Verification("ECDSA P-384 signature invalid".to_string()))
        }
        SigningScheme::Ed25519 => {
            // Ed25519 doesn't support prehashed mode in the same way
            // The signature is over the full message, not a hash
            // Fall back to regular verification
            verify_signature(public_key, digest, signature, scheme)
        }
        _ => {
            // For other schemes (RSA), use regular verification
            // RSA schemes in Sigstore typically sign the full message
            verify_signature(public_key, digest, signature, scheme)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyPair;

    #[test]
    fn test_verify_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let vk = VerificationKey::new(
            kp.public_key_bytes().to_vec(),
            SigningScheme::EcdsaP256Sha256,
        );
        assert!(vk.verify(data, sig.as_bytes()).is_ok());
    }

    #[test]
    fn test_verify_ed25519() {
        let kp = KeyPair::generate_ed25519().unwrap();
        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let vk = VerificationKey::new(kp.public_key_bytes().to_vec(), SigningScheme::Ed25519);
        assert!(vk.verify(data, sig.as_bytes()).is_ok());
    }

    #[test]
    fn test_verify_bad_signature() {
        let kp = KeyPair::generate_ed25519().unwrap();
        let data = b"test data";
        let bad_sig = vec![0u8; 64];

        let vk = VerificationKey::new(kp.public_key_bytes().to_vec(), SigningScheme::Ed25519);
        assert!(vk.verify(data, &bad_sig).is_err());
    }

    #[test]
    fn test_verify_wrong_data() {
        let kp = KeyPair::generate_ed25519().unwrap();
        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let vk = VerificationKey::new(kp.public_key_bytes().to_vec(), SigningScheme::Ed25519);
        assert!(vk.verify(b"wrong data", sig.as_bytes()).is_err());
    }
}
