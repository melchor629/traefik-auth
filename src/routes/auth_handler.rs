use std::{sync::Arc, cell::RefCell, collections::HashMap};

use actix_session::SessionExt;
use actix_web::{get, HttpRequest, HttpResponse, Responder, web, http::header, http::header::HeaderMap, cookie::{Cookie, SameSite, time::{OffsetDateTime, Duration}}};

use crate::{logic::{crypto::CryptoState, auth_pipeline::get_pipeline_for_request}, providers::{AuthProviders, AuthContext, AuthContextHeaders, AuthResponse, AuthSession}, config::AuthPipeline};

const LOG_TARGET: &str = "traefik_auth::handler::auth";
const COOKIE_NAME: &str = "ta-ls";
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
            return HttpResponse::InternalServerError()
                .body(format!("There was an error: {err}"))
        },
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

    let forwarded_method = context.headers.x_forwarded_method
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

    let mut payload = josekit::jwt::JwtPayload::new();
    payload.set_claim("sub", Some(sub.clone().into())).expect("?");
    for (claim_key, claim_value) in claims {
        payload.set_claim(&claim_key, Some(claim_value.into())).expect("?");
    }

    let mut header = josekit::jws::JwsHeader::new();
    header.set_algorithm("none");

    let Ok(token) = josekit::jwt::encode_unsecured(&payload, &header) else {
        return HttpResponse::InternalServerError()
            .body("Could not create auth cookie");
    };
    let Ok(cookie) = crypto_state.encrypt_and_sign(&token) else {
        return HttpResponse::InternalServerError()
            .body("Could not create auth cookie");
    };

    let sub2 = sub.as_str();
    let is_secure = context.headers.x_forwarded_proto.clone().unwrap_or_default()
        .to_ascii_lowercase()
        .eq("https");
    let mut cookie = Cookie::build(COOKIE_NAME, cookie)
        .same_site(SameSite::Lax)
        .secure(is_secure)
        .http_only(true)
        .path("/")
        .expires(OffsetDateTime::now_utc().checked_add(Duration::days(1)));
    if let Some(cookie_domain) = pipeline.cookie.domain.as_ref().or(context.headers.x_forwarded_host.as_ref()) {
        cookie = cookie.domain(cookie_domain);
    } else {
        log::debug!(target: LOG_TARGET, "Could not determine cookie domain for request, leaving blank, it may not work");
    }

    log::debug!(target: LOG_TARGET, "Procesed login and created cookie for user {sub}");
    if let Some(redirect_uri) = get_redirect_uri(&context) {
        // NOTE: to be able to set all cookies, it should redirect to the same URL (for some reason)
        //       this way, traefik sends the cookies to the browser and next time will have them
        HttpResponse::TemporaryRedirect()
            .append_header(("Location", redirect_uri))
            .cookie(cookie.finish())
            .append_header((USER_HEADER_NAME, sub2))
            .finish()
    } else {
        // if we don't have a redirect uri then just return OK, traefik will dismiss the cookie sadly
        HttpResponse::Ok()
            .cookie(cookie.finish())
            .append_header((USER_HEADER_NAME, sub2))
            .finish()
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
    let Some(cookie) = req.cookie(COOKIE_NAME) else {
        log::debug!(target: LOG_TARGET, "Starting login process due to cookie not found");
        return auth_redirect(&req, &auth_providers, &crypto_state, pipeline).await;
    };

    // decrypt cookie
    let Ok(token) = crypto_state.decrypt_and_verify(cookie.value()) else {
        log::debug!(target: LOG_TARGET, "Starting login process due to cookie is invalid (decrypt and verify)");
        return auth_redirect(&req, &auth_providers, &crypto_state, pipeline).await;
    };

    // validate token
    let Ok((token_payload, _)) = josekit::jwt::decode_unsecured(token) else {
        log::debug!(target: LOG_TARGET, "Starting login process due to cookie is invalid (decode jwt)");
        return auth_redirect(&req, &auth_providers, &crypto_state, pipeline).await;
    };

    let Some(sub) = token_payload.claim("sub") else {
        log::debug!(target: LOG_TARGET, "Starting login process due to cookie is invalid (sub claim not found)");
        return auth_redirect(&req, &auth_providers, &crypto_state, pipeline).await;
    };

    let Some(sub) = sub.as_str() else {
        log::debug!(target: LOG_TARGET, "Starting login process due to cookie is invalid (sub claim is not string)");
        return auth_redirect(&req, &auth_providers, &crypto_state, pipeline).await;
    };

    let claims = token_payload
        .claims_set()
        .iter()
        .filter_map(|p| p.1.as_str().map(|v| (p.0.clone(), v.to_string())))
        .collect::<HashMap<String, String>>();

    // check user is valid
    if let Some(http_response) = check_can_access(&pipeline, &sub, &claims) {
        return http_response;
    }

    log::debug!(target: LOG_TARGET, "User {sub} can access");
    HttpResponse::Ok()
        .append_header((USER_HEADER_NAME, sub))
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
        session.insert(key, value).expect("Session set should not fail");
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
    let Some(pipeline_claims) = &pipeline.claims else { return None; };

    if !pipeline_claims.sub.is_empty() && !pipeline_claims.sub.contains(&sub.to_string()) {
        log::debug!(target: LOG_TARGET, "User {sub} is not allowed to access to this resource");
        return Some(HttpResponse::Forbidden()
            .append_header(("X-Forwarded-User", sub))
            .body("You are not allowed to access here"));
    }

    for (claim_key, claim_values) in pipeline_claims.other.iter() {
        if !claims.contains_key(claim_key) || !claim_values.contains(&claims[claim_key]) {
            log::debug!(target: LOG_TARGET, "User {sub} does not have an allowed {claim_key} claim to access to this resource");
            return Some(HttpResponse::Forbidden()
                .append_header(("X-Forwarded-User", sub))
                .body("You are not allowed to access here"));
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
        },
        AuthResponse::Unauthorized => {
            log::debug!(target: LOG_TARGET, "Auth response is unauthorized");
            HttpResponse::Unauthorized().finish()
        },
        AuthResponse::Unknown(sub) => {
            log::debug!(target: LOG_TARGET, "Auth response is unknown {sub}");
            HttpResponse::Unauthorized()
                .body(format!("There is something wrong with data provided for user {sub}"))
        },
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