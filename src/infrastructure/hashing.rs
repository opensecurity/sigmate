use crate::error::AppError;
use digest::Digest;

pub fn hash_data(data: &[u8], algo: &str) -> Result<String, AppError> {
    let hash_string = match algo.to_lowercase().as_str() {
        "sha256" => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha512" => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha1" => {
            let mut hasher = sha1::Sha1::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        // This md5 crate has a different API from the RustCrypto digest crates.
        "md5" => {
            let digest = md5::compute(data);
            format!("{:x}", digest)
        }
        _ => {
            return Err(AppError::Crypto(format!(
                "Unsupported hash algorithm: {}",
                algo
            )))
        }
    };
    Ok(hash_string)
}