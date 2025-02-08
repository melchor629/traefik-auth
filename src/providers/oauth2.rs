use std::{cell::RefCell, sync::{Arc, Mutex}, collections::HashMap};

use async_trait::async_trait;
use oauth2::{basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl};

use crate::logic::oauth2_http_client::OAuth2HttpClient;

use super::{AuthContext, AuthProvider, AuthResponse, AuthError};

const LOG_TARGET: &str = "traefik_auth::oauth2";

type BasicOauthClient = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(Default)]
struct OAuth2ProviderInner {
    client: Option<BasicOauthClient>,
    openid_configuration: Option<OpenidConfiguration>,
    jwks: Option<josekit::jwk::JwkSet>,
    http_client: OAuth2HttpClient,
}

pub(crate) struct OAuth2Provider {
    issuer: String,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    redirect_url: RedirectUrl,
    scopes: Vec<String>,
    map_claims: HashMap<String, String>,
    inner: Arc<Mutex<RefCell<OAuth2ProviderInner>>>,
}

#[derive(serde::Deserialize, Clone)]
pub(crate) struct OpenidConfiguration {
    pub authorization_endpoint: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
}

impl OAuth2Provider {
    pub(crate) fn new(
        client_id: String,
        client_secret: Option<String>,
        issuer: String,
        scopes: Vec<String>,
        public_url: String,
        map_claims: HashMap<String, String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            client_id: ClientId::new(client_id),
            client_secret: client_secret.map(|secret| ClientSecret::new(secret)),
            redirect_url: RedirectUrl::new(format!("{}/oauth2/callback", public_url))?,
            issuer,
            scopes,
            map_claims,
            inner: Arc::new(Mutex::new(OAuth2ProviderInner::default().into())),
        })
    }

    async fn configure(&self) -> Result<BasicOauthClient, Box<dyn std::error::Error>> {
        let client = awc::Client::default();
        let inner_lock = self.inner.lock().unwrap();
        let mut inner = inner_lock.borrow_mut();

        if inner.openid_configuration.is_none() {
            log::debug!(target: LOG_TARGET, "Requesting OpenID Configuration to issuer {}", self.issuer);
            let url = format!("{}/.well-known/openid-configuration", self.issuer);
            let openid_configuration = client.get(url)
                .send()
                .await?
                .json::<OpenidConfiguration>()
                .await?;
            inner.openid_configuration = Some(openid_configuration);
        }

        let openid_configuration = inner.openid_configuration.as_ref().map(|v| v.clone()).unwrap();
        if inner.jwks.is_none() {
            log::debug!(target: LOG_TARGET, "Requesting JWKS to issuer {}", self.issuer);
            let jwks_bytes = client.get(openid_configuration.jwks_uri.clone())
                .send()
                .await?
                .body()
                .await?
                .to_vec();
            let jwks = josekit::jwk::JwkSet::from_bytes(&jwks_bytes)?;
            inner.jwks = Some(jwks);
        }

        if inner.client.is_none() {
            log::debug!(target: LOG_TARGET, "Creating OAuth2 client for issuer {}", self.issuer);
            let mut client = BasicClient::new(self.client_id.clone())
                .set_auth_uri(AuthUrl::new(openid_configuration.authorization_endpoint.clone())?)
                .set_token_uri(TokenUrl::new(openid_configuration.token_endpoint.clone())?)
                .set_redirect_uri(self.redirect_url.clone());
            if self.client_secret.is_some() {
                client = client.set_client_secret(self.client_secret.as_ref().unwrap().clone());
            }
            inner.client = Some(client);
        }

        Ok(inner.client.as_ref().unwrap().clone())
    }
}

#[async_trait(?Send)]
impl AuthProvider for OAuth2Provider {
    async fn handle(&self, ctx: &AuthContext) -> Result<AuthResponse, AuthError> {
        let client = self.configure().await?;
        let token = ctx.session.get("oauth2:token".into());
        let stored_issuer = ctx.session.get("oauth2:iss".into());
        if let Some(token) = token {
            log::debug!(target: LOG_TARGET, "Request has OAuth2 login process already started");

            // check response is for the configured token provider
            if stored_issuer.is_some() && stored_issuer.unwrap() != self.issuer {
                log::debug!(target: LOG_TARGET, "Issuer does not match, ignoring request...");
                return Ok(AuthResponse::Unauthorized);
            }

            ctx.session.delete("oauth2:token".into());
            ctx.session.delete("oauth2:iss".into());
            let Some(pkce_verifier) = ctx.session.get("oauth2:pkce_verifier".into()) else {
                log::debug!(target: LOG_TARGET, "No PKCE Verifier stored in session, ignoring...");
                return Ok(AuthResponse::Unauthorized);
            };

            log::debug!(target: LOG_TARGET, "Obtaining token from issuer {}", self.issuer);
            ctx.session.delete("oauth2:pkce_verifier".into());
            let token_result = client
                .exchange_code(AuthorizationCode::new(token))
                // Set the PKCE code verifier.
                .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
                .request_async(&self.inner.lock().unwrap().borrow().http_client)
                .await?;

            let inner_lock = self.inner.lock().unwrap();
            let inner = inner_lock.borrow();
            let jwks = inner.jwks.as_ref().unwrap();

            let token_bytes = token_result.access_token().secret().as_bytes();
            let header = josekit::jwt::decode_header(token_bytes)?;
            // TODO refactor semejante mostro
            let kid = header.claim("kid").unwrap().as_str().unwrap();
            let jwk_keys = jwks.get(&kid);
            let jwk = jwk_keys.first().unwrap();
            let verifier: Option<Box<dyn josekit::jws::JwsVerifier>> = match jwk.key_type() {
                "EC" => match jwk.algorithm().unwrap() {
                    "ES256" => Some(Box::new(josekit::jws::ES256.verifier_from_jwk(jwk)?)),
                    _ => None,
                },
                "OKT" => match jwk.algorithm().unwrap() {
                    "EdDSA" => Some(Box::new(josekit::jws::EdDSA.verifier_from_jwk(jwk)?)),
                    _ => None,
                },
                "RSA" => None,
                _ => None,
            };
            let Some(verifier) = verifier else {
                log::error!(target: LOG_TARGET, "Could not determine verifier for JWK {kid}");
                // TODO maybe error?
                return Ok(AuthResponse::Unauthorized);
            };

            let (payload, _) = josekit::jwt::decode_with_verifier(token_bytes, verifier.as_ref())?;

            // map claims from oauth2 token to our token
            let mut claims = HashMap::<String, String>::new();
            for (source_claim, target_claim) in self.map_claims.iter() {
                if let Some(claim) = payload.claim(&source_claim) {
                    if let Some(claim_str) = claim.as_str() {
                        claims.insert(target_claim.clone(), claim_str.into());
                    }
                }
            }

            return Ok(match payload.claim("sub") {
                Some(sub) => match sub.as_str() {
                    Some(sub_str) => AuthResponse::Success(sub_str.into(), claims),
                    None => AuthResponse::Unauthorized,
                },
                None => AuthResponse::Unauthorized,
            });
        }

        log::debug!(target: LOG_TARGET, "Starting new OAuth2 process for issuer {}", self.issuer);
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(self.scopes.clone().into_iter().map(Scope::new))
            .url();

        ctx.session.set("oauth2:pkce_verifier".into(), pkce_verifier.secret().clone());
        ctx.session.set("oauth2:csrf_token".into(), csrf_token.secret().clone());
        Ok(AuthResponse::Redirect(auth_url.to_string()))
    }
}
