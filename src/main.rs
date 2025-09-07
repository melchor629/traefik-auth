mod config;
mod logic;
mod providers;
mod routes;

use std::sync::Arc;

use crate::routes::*;
use actix_session::{
    SessionMiddleware, config::CookieContentSecurity, storage::CookieSessionStore,
};
use actix_web::{
    App, HttpServer, middleware,
    web::{self, ThinData},
};
use logic::crypto::CryptoState;
use providers::AuthProviders;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let settings = read_config();

    configure_logger(&settings);

    let rustls_config = Arc::new(rustls_config());
    let crypto = web::Data::new(match &settings.keys_path {
        None => CryptoState::default(),
        Some(path) => CryptoState::from_file(path)?,
    });
    let auth_providers = web::Data::new(AuthProviders::create(&settings));
    let public_url = awc::http::Uri::try_from(settings.public_url.clone()).ok();
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    crypto.cookie_key().clone(),
                )
                .cookie_secure(
                    settings
                        .cookie
                        .secure
                        .unwrap_or(settings.public_url.starts_with("https://")),
                )
                .cookie_domain(
                    settings
                        .cookie
                        .domain
                        .clone()
                        .or(public_url.clone().and_then(|u| u.host().map(|h| h.into()))),
                )
                .cookie_content_security(CookieContentSecurity::Private)
                .cookie_name("ta-s".into())
                .build(),
            )
            .service(auth_handler::handler)
            .service(oauth2_callback_handler::handler)
            .service(me_handler::handler)
            .app_data(auth_providers.clone())
            .app_data(crypto.clone())
            .app_data(ThinData(create_awc_client(&rustls_config)))
    })
    .bind("[::]:8080")?
    .run()
    .await
}

#[inline]
fn read_config() -> config::Settings {
    match config::Settings::read() {
        Ok(e) => e,
        Err(e) => {
            eprint!("Error in configuration:\n  ");
            match e {
                ::config::ConfigError::At { error, origin, key } => eprintln!(
                    "Cannot read {0} key from {1}: {error}",
                    key.unwrap_or("{unknown}".into()),
                    origin.unwrap_or("<unknown>".into())
                ),
                ::config::ConfigError::FileParse { uri, cause } => eprintln!(
                    "Cannot parse file {0}: {cause}.",
                    uri.unwrap_or("unknown".into())
                ),
                ::config::ConfigError::Foreign(err) => eprintln!("Unknown error: {err}."),
                ::config::ConfigError::Frozen => {
                    eprintln!("Configuration is frozen! (this is a bug)")
                }
                ::config::ConfigError::Message(msg) => eprintln!("{msg}."),
                ::config::ConfigError::NotFound(property) => {
                    eprintln!("Property not found: {property}.")
                }
                ::config::ConfigError::PathParse { cause } => {
                    eprintln!("Could not parse path: {}.", cause)
                }
                ::config::ConfigError::Type {
                    origin,
                    unexpected,
                    expected,
                    key,
                } => eprintln!(
                    "Property {1} has an invalid value: Expected type {expected} but found {unexpected} (source {0}).",
                    origin.unwrap_or("unknown".into()),
                    key.unwrap_or("?".into()),
                ),
                _ => eprintln!("Unknown error happened while parsing configuration"),
            };
            std::process::exit(1)
        }
    }
}

#[inline]
fn configure_logger(settings: &config::Settings) {
    let mut builder = env_logger::builder();
    for (key, value) in settings.logger.levels.iter() {
        builder.filter_module(key, *value);
    }
    builder.filter_level(settings.logger.level).init();
}

#[inline]
fn rustls_config() -> rustls::ClientConfig {
    use rustls_platform_verifier::ConfigVerifierExt as _;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    // The benefits of the platform verifier are clear; see:
    // https://github.com/rustls/rustls-platform-verifier#readme
    rustls::ClientConfig::with_platform_verifier().unwrap()
}

#[inline]
fn create_awc_client(client_tls_config: &Arc<rustls::ClientConfig>) -> awc::Client {
    awc::Client::builder()
        .add_default_header((awc::http::header::USER_AGENT, "traefik-auth"))
        .connector(awc::Connector::new().rustls_0_23(Arc::clone(client_tls_config)))
        .finish()
}
