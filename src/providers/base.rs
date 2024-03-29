use std::{sync::Arc, collections::HashMap};

use async_trait::async_trait;

use crate::config::{AuthProviderSettings, Settings, AuthPipeline};

use super::{basic_auth::BasicAuthProvider, oauth2::OAuth2Provider};

pub(crate) struct AuthContextHeaders {
    pub(crate) authorization: Option<String>,
    pub(crate) x_forwarded_method: Option<String>,
    pub(crate) x_forwarded_proto: Option<String>,
    pub(crate) x_forwarded_host: Option<String>,
    pub(crate) x_forwarded_uri: Option<String>,
    // pub(crate) x_forwarded_for: Option<String>,
}

pub(crate) struct AuthContext<'a> {
    pub(crate) pipeline: &'a AuthPipeline,
    pub(crate) headers: AuthContextHeaders,
    pub(crate) session: Arc<dyn AuthSession>,
}

pub(crate) trait AuthSession {
    fn get(&self, key: String) -> Option<String>;
    fn set(&self, key: String, value: String);
    fn delete(&self, key: String) -> bool;
}

#[derive(Clone)]
pub(crate) enum AuthResponse {
    Success(String, HashMap<String, String>),
    Redirect(String),
    Unknown(String),
    Unauthorized,
}

pub(crate) type AuthError = Box<dyn std::error::Error>;

#[async_trait(?Send)]
pub(crate) trait AuthProvider {
    async fn handle(&self, ctx: &AuthContext) -> Result<AuthResponse, AuthError>;
}

pub(crate) struct AuthProviders {
    providers: HashMap<String, Box<dyn AuthProvider + Sync + Send>>,
    pipelines: Vec<AuthPipeline>,
}

#[cfg(test)]
pub(crate) struct AuthSessionTest();

#[cfg(test)]
pub(crate) struct AuthProviderTest(pub(crate) Option<AuthResponse>);

impl AuthProviders {
    pub(crate) fn create(settings: &Settings) -> Self {
        let mut providers = HashMap::new();
        for (provider_id, provider_settings) in settings.providers.iter() {
            let provider: Box<dyn AuthProvider + Sync + Send> = match provider_settings {
                AuthProviderSettings::Basic(basic_settings) =>
                    if basic_settings.contents.is_some() {
                        let contents = basic_settings.contents.as_ref().unwrap().as_str();
                        Box::new(BasicAuthProvider::from_contents(
                            contents,
                            basic_settings.claims.clone(),
                        ))
                    } else if  basic_settings.file.is_some() {
                        let path = basic_settings.file.as_ref().unwrap();
                        Box::new(BasicAuthProvider::from_file(
                            path,
                            basic_settings.claims.clone()
                        ).expect("Could not parse htpasswd file"))
                    } else {
                        Box::new(BasicAuthProvider::from_contents(
                            "\n",
                            basic_settings.claims.clone()
                        ))
                    },
                AuthProviderSettings::OAuth2(oauth2_settings) =>
                    Box::new(OAuth2Provider::new(
                        oauth2_settings.client_id.clone(),
                        oauth2_settings.client_secret.clone(),
                        oauth2_settings.issuer.clone(),
                        oauth2_settings.scopes.clone(),
                        settings.public_url.clone(),
                        oauth2_settings.map_claims.clone(),
                    ).expect("There is something wrong in OAuth2 configuration")),
            };
            providers.insert(provider_id.clone(), provider);
        }

        Self {
            providers,
            pipelines: settings.pipelines.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn create_for_testing(pipelines: Vec<AuthPipeline>) -> Self {
        Self { providers: HashMap::default(), pipelines }
    }

    #[cfg(test)]
    pub(crate) fn create_for_testing2(providers: HashMap<String, Box<dyn AuthProvider + Sync + Send>>) -> Self {
        Self { providers, pipelines: vec![] }
    }

    pub(crate) async fn auth(&self, ctx: &AuthContext<'_>) -> Result<Option<AuthResponse>, AuthError> {
        for provider in ctx.pipeline.providers.iter().filter_map(|k| self.providers.get(k)) {
            let response = provider.handle(ctx).await?;
            // don't ask why, but it works
            let AuthResponse::Unauthorized = response else {
                return Ok(Some(response));
            };
        }

        Ok(None)
    }

    pub(crate) fn pipelines(&self) -> &Vec<AuthPipeline> {
        &self.pipelines
    }
}

#[cfg(test)]
impl AuthSession for AuthSessionTest {
    fn get(&self, _key: String) -> Option<String> { None }

    fn set(&self, _key: String, _value: String) {}

    fn delete(&self, _key: String) -> bool { true }
}

#[cfg(test)]
#[async_trait::async_trait(?Send)]
impl AuthProvider for AuthProviderTest {
    async fn handle(&self, _ctx: &AuthContext) -> Result<AuthResponse, AuthError> {
        match self.0.as_ref() {
            Some(result) => Ok(result.clone()),
            None => Err("fail".into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[actix_rt::test]
    async fn no_providers_returns_none() {
        let (providers, pipeline) = generate_provider_and_pipeline(vec![]);
        let context = generate_context(&pipeline);
        let result = providers.auth(&context).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[actix_rt::test]
    async fn provider_return_non_unauthorized_returns_unauthorized() {
        let (providers, pipeline) = generate_provider_and_pipeline(vec![
            AuthProviderTest(Some(
                AuthResponse::Unknown("self".into())
            )),
        ]);
        let context = generate_context(&pipeline);
        let result = providers.auth(&context).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        if let AuthResponse::Unknown(var) = result.unwrap() {
            assert_eq!(var, "self");
        } else {
            assert!(false);
        }
    }

    #[actix_rt::test]
    async fn provider_return_unauthorized_returns_none() {
        let (providers, pipeline) = generate_provider_and_pipeline(vec![
            AuthProviderTest(Some(
                AuthResponse::Unauthorized
            )),
        ]);
        let context = generate_context(&pipeline);
        let result = providers.auth(&context).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[actix_rt::test]
    async fn provider_return_non_unauthorized_returns_next_provider() {
        let (providers, pipeline) = generate_provider_and_pipeline(vec![
            AuthProviderTest(Some(
                AuthResponse::Unauthorized
            )),
            AuthProviderTest(Some(
                AuthResponse::Redirect("another place".into())
            )),
        ]);
        let context = generate_context(&pipeline);
        let result = providers.auth(&context).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        if let AuthResponse::Redirect(var) = result.unwrap() {
            assert_eq!(var, "another place");
        } else {
            assert!(false);
        }
    }

    #[actix_rt::test]
    async fn provider_fails_returns_failure() {
        let (providers, pipeline) = generate_provider_and_pipeline(vec![
            AuthProviderTest(None),
        ]);
        let context = generate_context(&pipeline);
        let result = providers.auth(&context).await;
        assert!(result.is_err());
    }

    fn generate_provider_and_pipeline(provider: Vec<AuthProviderTest>) -> (AuthProviders, AuthPipeline) {
        let mut providers = HashMap::<String, Box<dyn AuthProvider + Sync + Send>>::new();
        let mut provider_keys = Vec::new();
        for (i, p) in provider.into_iter().enumerate() {
            let key = format!("test-{i}");
            providers.insert(key.clone(), Box::new(p));
            provider_keys.push(key);
        }
        (AuthProviders::create_for_testing2(providers), AuthPipeline {
            rules: vec![],
            claims: None,
            providers: provider_keys,
            cookie: Default::default(),
        })
    }

    fn generate_context(pipeline: &AuthPipeline) -> AuthContext {
        AuthContext {
            headers: AuthContextHeaders {
                authorization: None,
                x_forwarded_host: None,
                x_forwarded_method: None,
                x_forwarded_proto: None,
                x_forwarded_uri: None,
            },
            pipeline,
            session: Arc::new(AuthSessionTest()),
        }
    }
}
