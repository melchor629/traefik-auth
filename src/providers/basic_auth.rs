use std::{path::PathBuf, fs::File, io::Read};

use async_trait::async_trait;

use super::{AuthContext, AuthProvider, AuthResponse, AuthError};

pub(crate) struct BasicAuthProvider {
    data: String,
}

impl BasicAuthProvider {
    pub(crate) fn from_contents(data: &str) -> Self {
        Self {
            data: data.into(),
        }
    }

    pub(crate) fn from_file(path: &PathBuf) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        Ok(Self::from_contents(buffer.as_str()))
    }

    fn check(&self, username: &str, password: &str) -> bool {
        let users = htpasswd_verify::load(&self.data);
        users.check(username, password)
    }
}

#[async_trait(?Send)]
impl AuthProvider for BasicAuthProvider {
    async fn handle(&self, ctx: &AuthContext) -> Result<AuthResponse, AuthError> {
        let Some(auth) = &ctx.headers.authorization else {
            return Ok(AuthResponse::Unauthorized);
        };

        let auth_split: Vec<&str> = auth.split(" ").collect();
        if auth_split.len() < 2 {
            return Ok(AuthResponse::Unauthorized);
        }

        if !auth_split[0].to_lowercase().eq("basic") {
            return Ok(AuthResponse::Unauthorized);
        }

        let bd = base64::decode(auth_split[1])?;
        let decoded = String::from_utf8(bd)?;

        let Some((username, password)) = decoded.split_once(":") else {
            return Ok(AuthResponse::Unauthorized);
        };

        if self.check(username, password) {
            Ok(AuthResponse::Success(username.into()))
        } else {
            Ok(AuthResponse::Unknown(username.into()))
        }
    }
}
