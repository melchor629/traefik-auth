use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use jaws::{
    Claims, SignatureBytes, TokenVerifier,
    key::{DeserializeJWK, JWKeyType},
    token::Unverified,
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
    basic::BasicClient,
};

use crate::logic::oauth2_http_client::OAuth2HttpClient;

use super::{AuthContext, AuthError, AuthProvider, AuthResponse};

const LOG_TARGET: &str = "traefik_auth::oauth2";

type BasicOauthClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(serde::Deserialize)]
struct JsonWebKey {
    #[serde(rename = "kty")]
    key_type: String,

    #[serde(rename = "kid")]
    key_id: String,

    #[serde(flatten)]
    parameters: BTreeMap<String, serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct JWKS {
    keys: Vec<JsonWebKey>,
}

type DynTokenVerifier = Box<dyn TokenVerifier<SignatureBytes>>;

#[derive(Default)]
struct OAuth2ProviderInner {
    client: Option<BasicOauthClient>,
    openid_configuration: Option<OpenidConfiguration>,
    jwks: Option<JWKS>,
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
            let openid_configuration = client
                .get(url)
                .send()
                .await?
                .json::<OpenidConfiguration>()
                .await?;
            inner.openid_configuration = Some(openid_configuration);
        }

        let openid_configuration = inner
            .openid_configuration
            .as_ref()
            .map(|v| v.clone())
            .unwrap();
        if inner.jwks.is_none() {
            log::debug!(target: LOG_TARGET, "Requesting JWKS to issuer {}", self.issuer);
            let jwks_bytes = client
                .get(openid_configuration.jwks_uri.clone())
                .send()
                .await?
                .body()
                .await?
                .to_vec();
            let jwks: JWKS = serde_json::from_slice(&jwks_bytes)?;
            inner.jwks = Some(jwks);
        }

        if inner.client.is_none() {
            log::debug!(target: LOG_TARGET, "Creating OAuth2 client for issuer {}", self.issuer);
            let mut client = BasicClient::new(self.client_id.clone())
                .set_auth_uri(AuthUrl::new(
                    openid_configuration.authorization_endpoint.clone(),
                )?)
                .set_token_uri(TokenUrl::new(openid_configuration.token_endpoint.clone())?)
                .set_redirect_uri(self.redirect_url.clone());
            if self.client_secret.is_some() {
                client = client.set_client_secret(self.client_secret.as_ref().unwrap().clone());
            }
            inner.client = Some(client);
        }

        Ok(inner.client.as_ref().unwrap().clone())
    }

    fn get_verifier_for_keyid(&self, kid: &str) -> Result<Option<DynTokenVerifier>, AuthError> {
        type EcEs256 = jaws::algorithms::ecdsa::VerifyingKey<p256::NistP256>;
        type EcEs384 = jaws::algorithms::ecdsa::VerifyingKey<p384::NistP384>;
        type RsaRs256 = jaws::algorithms::rsa::pkcs1v15::VerifyingKey<rsa::sha2::Sha256>;
        type RsaRs384 = jaws::algorithms::rsa::pkcs1v15::VerifyingKey<rsa::sha2::Sha384>;
        type RsaRs512 = jaws::algorithms::rsa::pkcs1v15::VerifyingKey<rsa::sha2::Sha512>;

        let inner_lock = self.inner.lock().unwrap();
        let inner = inner_lock.borrow();
        let jwks = inner.jwks.as_ref().unwrap();
        let jwk = jwks.get(kid).unwrap();
        let verifier: Option<DynTokenVerifier> = match jwk.key_type.as_str() {
            EcEs256::KEY_TYPE => match jwk.algorithm().unwrap() {
                "ES256" => Some(Box::new(EcEs256::build(jwk.parameters.clone())?)),
                "ES384" => Some(Box::new(EcEs384::build(jwk.parameters.clone())?)),
                _ => None,
            },
            RsaRs256::KEY_TYPE => match jwk.algorithm() {
                Some("RS384") => Some(Box::new(RsaRs384::new(rsa::RsaPublicKey::build(
                    jwk.parameters.clone(),
                )?))),
                Some("RS512") => Some(Box::new(RsaRs512::new(rsa::RsaPublicKey::build(
                    jwk.parameters.clone(),
                )?))),
                _ => Some(Box::new(RsaRs256::new(rsa::RsaPublicKey::build(
                    jwk.parameters.clone(),
                )?))),
            },
            _ => None,
        };
        Ok(verifier)
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

            let token_string = token_result.access_token().secret();
            let token =
                jaws::Token::<Claims<serde_json::Value>, Unverified<()>>::from_str(&token_string)?;

            let token_header = token.header();
            let kid = token_header.key_id().unwrap();
            let Some(verifier) = self.get_verifier_for_keyid(kid)? else {
                log::error!(target: LOG_TARGET, "Could not determine verifier for JWK {kid}");
                // TODO maybe error?
                return Ok(AuthResponse::Unauthorized);
            };

            let token = token.verify::<_, SignatureBytes>(verifier.as_ref())?;

            // map claims from oauth2 token to our token
            let mut claims = HashMap::<String, String>::new();
            if let Some(token_payload) = token.payload() {
                for (source_claim, target_claim) in self.map_claims.iter() {
                    let claim_value = match source_claim.as_str() {
                        "sub" => token_payload.registered.subject.clone(),
                        "aud" => token_payload.registered.audience.clone(),
                        _ => token_payload
                            .claims
                            .get(source_claim)
                            .map(|v| v.as_str().unwrap().to_string()),
                    };
                    if let Some(claim) = claim_value {
                        claims.insert(target_claim.clone(), claim);
                    }
                }
            }

            return Ok(
                match token.payload().and_then(|p| p.registered.subject.clone()) {
                    Some(sub) => AuthResponse::Success(sub.into(), claims),
                    None => AuthResponse::Unauthorized,
                },
            );
        }

        log::debug!(target: LOG_TARGET, "Starting new OAuth2 process for issuer {}", self.issuer);
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(self.scopes.clone().into_iter().map(Scope::new))
            .url();

        ctx.session.set(
            "oauth2:pkce_verifier".into(),
            pkce_verifier.secret().clone(),
        );
        ctx.session
            .set("oauth2:csrf_token".into(), csrf_token.secret().clone());
        Ok(AuthResponse::Redirect(auth_url.to_string()))
    }
}

impl JWKS {
    fn get<'a>(&'a self, kid: &str) -> Option<&'a JsonWebKey> {
        self.keys.iter().find(|k| k.key_id == kid)
    }
}

impl JsonWebKey {
    fn algorithm<'a>(&'a self) -> Option<&'a str> {
        self.parameters.get("alg").and_then(|v| v.as_str())
    }
}
