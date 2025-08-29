use std::{path::PathBuf, fs::File, io::Read, collections::HashMap};

use async_trait::async_trait;
use base64::Engine;

use super::{AuthContext, AuthProvider, AuthResponse, AuthError};
use crate::logic::htpasswd::Htpasswd;

pub(crate) struct BasicAuthProvider {
    claims: HashMap<String, String>,
    htpasswd: Htpasswd<'static>
}

impl BasicAuthProvider {
    pub(crate) fn from_contents(data: &str, claims: HashMap<String, String>) -> Self {
        Self {
            claims,
            htpasswd: Htpasswd::new(data).into_owned(),
        }
    }

    pub(crate) fn from_file(path: &PathBuf, claims: HashMap<String, String>) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        Ok(Self::from_contents(buffer.as_str(), claims))
    }

    fn check(&self, username: &str, password: &str) -> bool {
        self.htpasswd.check(username, password)
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

        let bd = base64::engine::general_purpose::STANDARD.decode(auth_split[1])?;
        let decoded = String::from_utf8(bd)?;

        let Some((username, password)) = decoded.split_once(":") else {
            return Ok(AuthResponse::Unauthorized);
        };

        if self.check(username, password) {
            Ok(AuthResponse::Success(username.into(), self.claims.clone()))
        } else {
            Ok(AuthResponse::Unknown(username.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{providers::{AuthContextHeaders, AuthSessionTest}, config::AuthPipeline};

    use super::*;

    static HTPASSWD: &str = "user_bcrypt:$2y$05$QzPnkkUycoy1OlP26Ruw6eqvy8GNqTFPwcfITNqzpkKLNHc3F0Hke\n";

    #[actix_rt::test]
    async fn correct_header_value_returns_success() {
        let provider = BasicAuthProvider::from_contents(HTPASSWD, Default::default());
        let pipeline = generate_pipeline();
        let ctx = generate_context(Some("Basic dXNlcl9iY3J5cHQ6MTIzNA==".into()), &pipeline);

        let result = provider.handle(&ctx).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        if let AuthResponse::Success(username, _) = result {
            assert_eq!(username, "user_bcrypt");
        } else {
            assert!(false);
        }
    }

    #[actix_rt::test]
    async fn incorrect_password_header_value_returns_unknown() {
        let provider = BasicAuthProvider::from_contents(HTPASSWD, Default::default());
        let pipeline = generate_pipeline();
        let ctx = generate_context(Some("Basic dXNlcl9iY3J5cHQ6MTIz".into()), &pipeline);

        let result = provider.handle(&ctx).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        if let AuthResponse::Unknown(username) = result {
            assert_eq!(username, "user_bcrypt");
        } else {
            assert!(false);
        }
    }

    #[actix_rt::test]
    async fn invalid_basic_header_value_returns_unknown() {
        let provider = BasicAuthProvider::from_contents(HTPASSWD, Default::default());
        let pipeline = generate_pipeline();
        let ctx = generate_context(Some("Basic dXNlci0xMjM=".into()), &pipeline);

        let result = provider.handle(&ctx).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let AuthResponse::Unauthorized = result else {
            assert!(false);
            return;
        };
    }

    #[actix_rt::test]
    async fn invalid_basic_header_value_returns_unauthorized() {
        let provider = BasicAuthProvider::from_contents(HTPASSWD, Default::default());
        let pipeline = generate_pipeline();
        let ctx = generate_context(Some("Basic dXNlci0xMjM=".into()), &pipeline);

        let result = provider.handle(&ctx).await;
        assert!(result.is_ok());
        let Ok(AuthResponse::Unauthorized) = result else {
            assert!(false);
            return;
        };
    }

    #[actix_rt::test]
    async fn invalid_authorization_header_type_returns_unauthorized() {
        let provider = BasicAuthProvider::from_contents(HTPASSWD, Default::default());
        let pipeline = generate_pipeline();
        let ctx = generate_context(Some("Digest ...".into()), &pipeline);

        let result = provider.handle(&ctx).await;
        assert!(result.is_ok());
        let Ok(AuthResponse::Unauthorized) = result else {
            assert!(false);
            return;
        };
    }

    #[actix_rt::test]
    async fn invalid_authorization_header_value_returns_unauthorized() {
        let provider = BasicAuthProvider::from_contents(HTPASSWD, Default::default());
        let pipeline = generate_pipeline();
        let ctx = generate_context(Some("garbage".into()), &pipeline);

        let result = provider.handle(&ctx).await;
        assert!(result.is_ok());
        let Ok(AuthResponse::Unauthorized) = result else {
            assert!(false);
            return;
        };
    }

    #[actix_rt::test]
    async fn no_authorization_header_returns_unauthorized() {
        let provider = BasicAuthProvider::from_contents(HTPASSWD, Default::default());
        let pipeline = generate_pipeline();
        let ctx = generate_context(None, &pipeline);

        let result = provider.handle(&ctx).await;
        assert!(result.is_ok());
        let Ok(AuthResponse::Unauthorized) = result else {
            assert!(false);
            return;
        };
    }

    fn generate_context(value: Option<String>, pipeline: &'_ AuthPipeline) -> AuthContext<'_> {
        AuthContext {
            headers: AuthContextHeaders {
                authorization: value,
                x_forwarded_host: None,
                x_forwarded_method: None,
                x_forwarded_proto: None,
                x_forwarded_uri: None,
            },
            pipeline,
            session: Arc::new(AuthSessionTest()),
        }
    }

    fn generate_pipeline() -> AuthPipeline {
        AuthPipeline {
            rules: vec![],
            claims: None,
            providers: vec![],
            cookie: Default::default(),
        }
    }
}
