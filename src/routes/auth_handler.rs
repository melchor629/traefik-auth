use std::{cell::RefCell, collections::HashMap, sync::Arc};

use actix_session::SessionExt;
use actix_web::{
    HttpRequest, HttpResponse, Responder, get, http::header, http::header::HeaderMap, web,
};

use crate::{
    config::AuthPipeline,
    logic::{
        auth_pipeline::get_pipeline_for_request,
        cookie::{SessionCookie, parse_session_cookie, set_session_cookie},
        crypto::CryptoState,
    },
    providers::{AuthContext, AuthContextHeaders, AuthProviders, AuthResponse, AuthSession},
};

const LOG_TARGET: &str = "traefik_auth::handler::auth";
const USER_HEADER_NAME: &str = "X-Forwarded-User";

pub(crate) async fn auth_redirect(
    req: &HttpRequest,
    auth_providers: &AuthProviders,
    crypto_state: &CryptoState,
    pipeline: &AuthPipeline,
) -> HttpResponse {
    let context = AuthContext {
        pipeline,
        headers: get_headers(req.headers()),
        session: Arc::new(ActixAuthSession {
            session: req.get_session().clone().into(),
        }),
    };
    let response_result = auth_providers.auth(&context).await;
    let response = match response_result {
        Ok(r) => r,
        Err(err) => {
            log::error!(target: LOG_TARGET, "There was an error while processing login: {err}");
            return HttpResponse::InternalServerError().body(format!("There was an error: {err}"));
        }
    };
    let Some(response) = response else {
        log::debug!(target: LOG_TARGET, "No auth providers respond to this request");
        return HttpResponse::Unauthorized()
            .body("No configured auth providers authorized this request");
    };

    let AuthResponse::Success(sub, claims) = response else {
        return build_response(response, &context);
    };

    // check user is valid
    if let Some(http_response) = check_can_access(&pipeline, &sub, &claims) {
        return http_response;
    }

    let forwarded_method = context
        .headers
        .x_forwarded_method
        .as_ref()
        .unwrap_or(&"get".into())
        .to_ascii_lowercase();
    if pipeline.cookie.ignore || forwarded_method != "get" {
        // TODO should we ignore this if not GET or leave to ignore thing?
        // if the method is different than get, probably will be a request to an API - ignore for now
        log::debug!(target: LOG_TARGET, "The Forwarded Method is {forwarded_method}, ignoring cookie creation");
        return HttpResponse::Ok()
            .append_header((USER_HEADER_NAME, sub))
            .finish();
    }

    let sub = sub.as_str();
    let is_secure = context
        .headers
        .x_forwarded_proto
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .eq("https");
    let cookie = set_session_cookie(
        SessionCookie {
            sub: sub.to_string(),
            claims,
            domain: pipeline
                .cookie
                .domain
                .clone()
                .or(context.headers.x_forwarded_host.clone()),
            is_secure,
        },
        &crypto_state,
    );
    let Ok(cookie) = cookie else {
        return HttpResponse::InternalServerError().body("Could not create auth cookie");
    };

    log::debug!(target: LOG_TARGET, "Procesed login and created cookie for user {sub}");
    match get_redirect_uri(&context) {
        Some(redirect_uri) => {
            // NOTE: to be able to set all cookies, it should redirect to the same URL (for some reason)
            //       this way, traefik sends the cookies to the browser and next time will have them
            HttpResponse::TemporaryRedirect()
                .append_header(("Location", redirect_uri))
                .cookie(cookie)
                .append_header((USER_HEADER_NAME, sub))
                .finish()
        }
        _ => {
            // if we don't have a redirect uri then just return OK, traefik will dismiss the cookie sadly
            HttpResponse::Ok()
                .cookie(cookie)
                .append_header((USER_HEADER_NAME, sub))
                .finish()
        }
    }
}

#[get("/auth")]
pub(crate) async fn handler(
    req: HttpRequest,
    crypto_state: web::Data<CryptoState>,
    auth_providers: web::Data<AuthProviders>,
) -> impl Responder {
    // get pipeline for request
    let auth_headers = get_headers(req.headers());
    let Some(pipeline) = get_pipeline_for_request(&auth_headers, &auth_providers) else {
        log::warn!(target: LOG_TARGET, "The received request did not match any of the configured auth pipelines");
        return HttpResponse::InternalServerError()
            .body("No auth pipeline configured that can handle this request");
    };

    log::debug!(target: LOG_TARGET, "Using pipeline {:?}", pipeline);
    let Some(cookie) = parse_session_cookie(&req, &crypto_state) else {
        log::debug!(target: LOG_TARGET, "There is something wrong with the cookie, start login process");
        return auth_redirect(&req, &auth_providers, &crypto_state, pipeline).await;
    };

    // check user is valid
    if let Some(http_response) = check_can_access(&pipeline, &cookie.sub, &cookie.claims) {
        return http_response;
    }

    log::debug!(target: LOG_TARGET, "User {} can access", cookie.sub);
    HttpResponse::Ok()
        .append_header((USER_HEADER_NAME, cookie.sub))
        .finish()
}

struct ActixAuthSession {
    session: RefCell<actix_session::Session>,
}

impl AuthSession for ActixAuthSession {
    fn get(&self, key: String) -> Option<String> {
        let session = self.session.borrow();
        session.get::<String>(&key).unwrap_or_default()
    }

    fn set(&self, key: String, value: String) {
        let session = self.session.borrow();
        session
            .insert(key, value)
            .expect("Session set should not fail");
    }

    fn delete(&self, key: String) -> bool {
        let session = self.session.borrow();
        session.remove(&key).is_some()
    }
}

#[inline]
fn header_to_string(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.to_str().ok().map(|s| s.into()))
}

#[inline]
fn get_headers(headers: &HeaderMap) -> AuthContextHeaders {
    AuthContextHeaders {
        authorization: header_to_string(headers, "authorization"),
        x_forwarded_method: header_to_string(headers, "x-forwarded-method"),
        x_forwarded_proto: header_to_string(headers, "x-forwarded-proto"),
        x_forwarded_host: header_to_string(headers, "x-forwarded-host"),
        x_forwarded_uri: header_to_string(headers, "x-forwarded-uri"),
        // x_forwarded_for: header_to_string(headers, "x-forwarded-for"),
    }
}

#[inline]
fn check_can_access(
    pipeline: &AuthPipeline,
    sub: &str,
    claims: &HashMap<String, String>,
) -> Option<HttpResponse> {
    let Some(pipeline_claims) = &pipeline.claims else {
        return None;
    };

    if !pipeline_claims.sub.is_empty() && !pipeline_claims.sub.contains(&sub.to_string()) {
        log::debug!(target: LOG_TARGET, "User {sub} is not allowed to access to this resource");
        return Some(
            HttpResponse::Forbidden()
                .append_header(("X-Forwarded-User", sub))
                .body("You are not allowed to access here"),
        );
    }

    for (claim_key, claim_values) in pipeline_claims.other.iter() {
        if !claims.contains_key(claim_key) || !claim_values.contains(&claims[claim_key]) {
            log::debug!(target: LOG_TARGET, "User {sub} does not have an allowed {claim_key} claim to access to this resource");
            return Some(
                HttpResponse::Forbidden()
                    .append_header(("X-Forwarded-User", sub))
                    .body("You are not allowed to access here"),
            );
        }
    }

    None
}

#[inline]
fn build_response(auth_response: AuthResponse, context: &AuthContext) -> HttpResponse {
    match auth_response {
        AuthResponse::Redirect(url) => {
            log::debug!(target: LOG_TARGET, "Auth response to redirect to {url}");
            if let Some(uri) = get_redirect_uri(context) {
                log::debug!(target: LOG_TARGET, "Storing redirect uri {uri}");
                context.session.set("auth:redirect_uri".into(), uri);
            }

            HttpResponse::TemporaryRedirect()
                .append_header((header::LOCATION, url))
                .finish()
        }
        AuthResponse::Unauthorized => {
            log::debug!(target: LOG_TARGET, "Auth response is unauthorized");
            HttpResponse::Unauthorized().finish()
        }
        AuthResponse::Unknown(sub) => {
            log::debug!(target: LOG_TARGET, "Auth response is unknown {sub}");
            HttpResponse::Unauthorized().body(format!(
                "There is something wrong with data provided for user {sub}"
            ))
        }
        // this branch should never run
        AuthResponse::Success(_, _) => HttpResponse::Ok().finish(),
    }
}

#[inline]
fn get_redirect_uri(context: &AuthContext) -> Option<String> {
    let Some(path) = &context.headers.x_forwarded_uri else {
        return None;
    };

    let Some(proto) = &context.headers.x_forwarded_proto else {
        return None;
    };

    let Some(host) = &context.headers.x_forwarded_host else {
        return None;
    };

    let Some(method) = &context.headers.x_forwarded_method else {
        return None;
    };

    if method.to_lowercase() == "get" {
        Some(format!("{proto}://{host}{path}"))
    } else {
        None
    }
}
