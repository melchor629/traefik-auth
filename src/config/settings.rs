use std::{collections::HashMap, path::PathBuf};

use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct LoggerSettings {
    pub level: log::LevelFilter,
    pub levels: HashMap<String, log::LevelFilter>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct BasicAuthProviderSettings {
    pub contents: Option<String>,
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub claims: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct OAuth2ProviderSettings {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub issuer: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub map_claims: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) enum AuthProviderSettings {
    #[serde(rename = "basic")]
    Basic(BasicAuthProviderSettings),
    #[serde(rename = "oauth2")]
    OAuth2(OAuth2ProviderSettings),
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) enum AuthRule {
    #[serde(rename = "http_method")]
    HttpMethod(Vec<String>),
    #[serde(rename = "http_path")]
    HttpPath(String),
    #[serde(rename = "http_path_prefix")]
    HttpPathPrefix(String),
    #[serde(rename = "http_host")]
    HttpHost(String),
    #[serde(rename = "http_protocol")]
    HttpProtocol(String),
    #[serde(rename = "or")]
    Or(Vec<AuthRule>),
    #[serde(rename = "and")]
    And(Vec<AuthRule>),
}

#[derive(Clone, Default, Debug, Deserialize)]
pub(crate) struct AuthPipelineCookie {
    pub ignore: bool,
    pub domain: Option<String>,
}

#[derive(Clone, Default, Debug, Deserialize)]
pub(crate) struct AuthClaims {
    #[serde(default)]
    pub sub: Vec<String>,
    #[serde(flatten, default)]
    pub other: HashMap<String, String>
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AuthPipeline {
    #[serde(default)]
    pub rules: Vec<AuthRule>,
    pub claims: Option<AuthClaims>,
    pub providers: Vec<String>,
    #[serde(default)]
    pub cookie: AuthPipelineCookie,
}

#[derive(Clone, Default, Debug, Deserialize)]
pub(crate) struct CookieSettings {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub secure: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Settings {
    pub logger: LoggerSettings,
    pub cookie: CookieSettings,
    pub providers: HashMap<String, AuthProviderSettings>,
    pub pipelines: Vec<AuthPipeline>,
    pub public_url: String,
    pub keys_path: Option<PathBuf>,
}

impl Settings {
    pub(crate) fn read() -> Result<Self, ConfigError> {
        let settings = Config::builder()
            .add_source(File::with_name("config/default.yml").required(true))
            .add_source(File::with_name("config/config.yml").required(false))
            .add_source(File::with_name("config/config.json").required(false))
            .add_source(Environment::with_prefix("traefik_auth"))
            .build()?;

        settings.try_deserialize()
    }
}
