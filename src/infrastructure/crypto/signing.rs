use crate::error::AppError;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

pub fn verify_signature(
    verifying_key: &VerifyingKey,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, AppError> {
    let sig = Signature::from_slice(signature)
        .map_err(|_| AppError::Crypto("Invalid signature format.".to_string()))?;

    Ok(verifying_key.verify(data, &sig).is_ok())
}
