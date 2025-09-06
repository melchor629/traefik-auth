use std::{
    fmt::Display,
    fs::File,
    io::{ErrorKind, Read, Write},
    path::Path,
    string::FromUtf8Error,
};

use base64::{DecodeError, Engine, engine::general_purpose::URL_SAFE as BASE64_ENGINE};
use orion::{aead, auth, errors};

pub(crate) struct CryptoState {
    encrypt_key: aead::SecretKey,
    hash_key: auth::SecretKey,
    cookie_key: actix_web::cookie::Key,
}

#[derive(Debug, Clone)]
pub(crate) enum CryptoError {
    BadSyntax,
    BadContent(DecodeError),
    CryptographyError(errors::UnknownCryptoError),
    InvalidUtf8(FromUtf8Error),
}

impl CryptoState {
    pub(crate) fn from_file(path: &Path) -> std::io::Result<CryptoState> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) => match err.kind() {
                ErrorKind::NotFound => return Ok(CryptoState::default().write_to(path)?),
                _ => return Err(err),
            },
        };

        let mut encrypt_key_buf = [0_u8; 32];
        let mut hash_key_buf = [0_u8; 32];
        let mut cookie_key_buf = [0_u8; 64];
        let read_result = file
            .read_exact(&mut encrypt_key_buf)
            .and_then(|_| file.read_exact(&mut hash_key_buf))
            .and_then(|_| file.read_exact(&mut cookie_key_buf));
        match read_result {
            Err(err) => match err.kind() {
                ErrorKind::UnexpectedEof => return Ok(CryptoState::default().write_to(path)?),
                _ => return Err(err),
            },
            _ => (),
        };

        Ok(CryptoState {
            encrypt_key: aead::SecretKey::from_slice(&encrypt_key_buf).expect("aead::SecretKey"),
            hash_key: auth::SecretKey::from_slice(&hash_key_buf).expect("auth::SecretKey"),
            cookie_key: actix_web::cookie::Key::from(&cookie_key_buf),
        })
    }

    fn write_to(self, path: &Path) -> std::io::Result<Self> {
        let mut file = File::create(path)?;
        file.write_all(self.encrypt_key.unprotected_as_bytes())?;
        file.write_all(self.hash_key.unprotected_as_bytes())?;
        file.write_all(self.cookie_key.master())?;
        Ok(self)
    }

    pub(crate) fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(aead::open(&self.encrypt_key, data)?)
    }

    pub(crate) fn verify(&self, data: &[u8], hash: &[u8]) -> Result<(), CryptoError> {
        let tag = auth::Tag::from_slice(hash)?;
        Ok(auth::authenticate_verify(&tag, &self.hash_key, &data)?)
    }

    pub(crate) fn decrypt_and_verify(&self, value: &str) -> Result<String, CryptoError> {
        let Some((content, hash)) = value.split_once(".") else {
            return Err(CryptoError::BadSyntax);
        };

        let content_bytes = BASE64_ENGINE.decode(content)?;
        let hash_bytes = BASE64_ENGINE.decode(hash)?;

        let decrypted = self.decrypt(&content_bytes)?;
        self.verify(&decrypted, &hash_bytes)?;

        Ok(String::from_utf8(decrypted)?)
    }

    pub(crate) fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(aead::seal(&self.encrypt_key, data)?)
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(auth::authenticate(&self.hash_key, data)?
            .unprotected_as_bytes()
            .into())
    }

    pub(crate) fn encrypt_and_sign(&self, value: &str) -> Result<String, CryptoError> {
        let data = value.as_bytes();
        let encrypted = self.encrypt(&data)?;
        let signed = self.sign(data)?;

        let encrypted = BASE64_ENGINE.encode(encrypted);
        let signed = BASE64_ENGINE.encode(signed);
        Ok(format!("{}.{}", encrypted, signed))
    }

    pub(crate) fn cookie_key(&self) -> &actix_web::cookie::Key {
        &self.cookie_key
    }
}

impl Clone for CryptoState {
    fn clone(&self) -> Self {
        Self {
            encrypt_key: aead::SecretKey::from_slice(self.encrypt_key.unprotected_as_bytes())
                .expect("."),
            hash_key: auth::SecretKey::from_slice(self.hash_key.unprotected_as_bytes()).expect("."),
            cookie_key: self.cookie_key.clone(),
        }
    }
}

impl Default for CryptoState {
    fn default() -> Self {
        Self {
            encrypt_key: Default::default(),
            hash_key: Default::default(),
            cookie_key: actix_web::cookie::Key::generate(),
        }
    }
}

impl From<errors::UnknownCryptoError> for CryptoError {
    fn from(error: errors::UnknownCryptoError) -> Self {
        Self::CryptographyError(error)
    }
}

impl From<FromUtf8Error> for CryptoError {
    fn from(error: FromUtf8Error) -> Self {
        Self::InvalidUtf8(error)
    }
}

impl From<DecodeError> for CryptoError {
    fn from(error: DecodeError) -> Self {
        Self::BadContent(error)
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::BadSyntax => write!(f, "The value has an invalid format"),
            CryptoError::CryptographyError(err) => {
                write!(f, "Failed decrypting and verifying {err}")
            }
            CryptoError::InvalidUtf8(err) => write!(f, "Data contains invalid characters: {err}"),
            CryptoError::BadContent(err) => write!(f, "Invalid base64 content: {err}"),
        }
    }
}
