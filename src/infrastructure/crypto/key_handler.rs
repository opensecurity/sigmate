use crate::error::AppError;
use crate::infrastructure::hashing;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use openssl::pkey::{PKey, Private};
use rpassword::prompt_password;
use std::env;

pub fn load_signing_key(
    key_pem: &[u8],
    password_env_var: Option<&str>,
) -> Result<SigningKey, AppError> {
    // Attempt to load the key without a password first.
    if let Ok(pkey) = PKey::private_key_from_pem(key_pem) {
        return pkey_to_signing_key(&pkey);
    }

    // If that fails, it's likely encrypted. We now need a password.
    let password = if let Some(env_var) = password_env_var {
        env::var(env_var).ok()
    } else {
        prompt_password("Enter password for private key: ").ok()
    };

    let password_bytes = password.ok_or(AppError::KeyPasswordRequired)?;

    // Use the correct OpenSSL function which takes PEM data and a passphrase byte slice.
    let pkey = PKey::private_key_from_pem_passphrase(key_pem, password_bytes.as_bytes())
        .map_err(|_| AppError::KeyPasswordRequired)?;

    pkey_to_signing_key(&pkey)
}

fn pkey_to_signing_key(pkey: &PKey<Private>) -> Result<SigningKey, AppError> {
    let pkcs8_bytes = pkey
        .private_key_to_pkcs8()
        .map_err(|_| AppError::Crypto("Failed to serialize key to PKCS#8".into()))?;

    if pkcs8_bytes.len() < 32 {
        return Err(AppError::Crypto("Invalid PKCS#8 key length".into()));
    }
    let secret_key_bytes = &pkcs8_bytes[pkcs8_bytes.len() - 32..];
    let secret_key: [u8; 32] = secret_key_bytes.try_into().map_err(|_| {
        AppError::Crypto("Failed to extract 32-byte secret from PKCS#8 key".into())
    })?;

    Ok(SigningKey::from_bytes(&secret_key))
}

pub fn load_verifying_key(key_pem: &[u8]) -> Result<VerifyingKey, AppError> {
    let pkey = PKey::public_key_from_pem(key_pem)
        .map_err(|_| AppError::Crypto("Failed to load public key from PEM".into()))?;
    let pub_key_bytes = pkey
        .raw_public_key()
        .map_err(|_| AppError::Crypto("Failed to get raw public key".into()))?;

    VerifyingKey::try_from(pub_key_bytes.as_slice())
        .map_err(|_| AppError::Crypto("Could not construct verifying key from raw bytes".to_string()))
}

pub fn get_key_fingerprint(verifying_key: &VerifyingKey) -> Result<String, AppError> {
    hashing::hash_data(verifying_key.as_bytes(), "sha256")
}

pub fn get_verifying_key_from_pem(key_pem: &[u8]) -> Result<VerifyingKey, AppError> {
    if let Ok(key) = load_verifying_key(key_pem) {
        return Ok(key);
    }
    if let Ok(key) = load_signing_key(key_pem, None) {
        return Ok(key.verifying_key());
    }
    Err(AppError::Crypto(
        "PEM data is not a valid Ed25519 public or private key.".to_string(),
    ))
}

pub fn sign_data(signing_key: &SigningKey, data: &[u8]) -> Signature {
    signing_key.sign(data)
}