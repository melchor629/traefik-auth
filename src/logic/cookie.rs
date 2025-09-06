use std::collections::HashMap;

use actix_web::{
    HttpRequest,
    cookie::{
        Cookie, SameSite,
        time::{Duration, OffsetDateTime},
    },
};

use crate::logic::crypto::CryptoState;

const LOG_TARGET: &str = "traefik_auth::logic::cookie";
const COOKIE_NAME: &str = "ta-ls";

pub(crate) struct SessionCookie {
    pub(crate) sub: String,
    pub(crate) claims: HashMap<String, String>,
    pub(crate) domain: Option<String>,
    pub(crate) is_secure: bool,
}

#[inline]
pub(crate) fn read_session_cookie(req: &HttpRequest) -> Option<Cookie<'static>> {
    req.cookie(COOKIE_NAME)
}

type Payload = HashMap<String, serde_json::Value>;

#[inline]
pub(crate) fn set_session_cookie<'a>(
    value: SessionCookie,
    crypto_state: &CryptoState,
) -> Result<Cookie<'a>, &'static str> {
    let mut payload = Payload::new();
    for (claim_key, claim_value) in value.claims {
        payload.insert(claim_key, claim_value.into());
    }
    payload.insert("sub".to_string(), value.sub.into());

    let Ok(token) = serde_json::to_string(&payload) else {
        return Err("Could not create JWT");
    };
    let Ok(cookie) = crypto_state.encrypt_and_sign(&token) else {
        return Err("Could not encrypt cookie");
    };

    let mut cookie = Cookie::build(COOKIE_NAME, cookie)
        .same_site(SameSite::Lax)
        .secure(value.is_secure)
        .http_only(true)
        .path("/")
        .expires(OffsetDateTime::now_utc().checked_add(Duration::days(1)));

    if value.domain.is_some() {
        cookie = cookie.domain(value.domain.unwrap());
    } else {
        log::debug!(target: LOG_TARGET, "Could not determine cookie domain for request, leaving blank, it may not work");
    }

    Ok(cookie.finish())
}

pub(crate) fn parse_session_cookie(
    req: &HttpRequest,
    crypto_state: &CryptoState,
) -> Option<SessionCookie> {
    // read cookie
    let Some(cookie) = read_session_cookie(req) else {
        log::debug!(target: LOG_TARGET, "Session cookie not found");
        return None;
    };

    // decrypt cookie
    let Ok(token) = crypto_state.decrypt_and_verify(cookie.value()) else {
        log::debug!(target: LOG_TARGET, "Session cookie is invalid (decrypt and verify)");
        return None;
    };

    // validate token
    let Ok(token_payload) = serde_json::from_str::<Payload>(&token) else {
        log::debug!(target: LOG_TARGET, "Session cookie is invalid (decode jwt)");
        return None;
    };

    let Some(sub) = token_payload.get("sub") else {
        log::debug!(target: LOG_TARGET, "Session cookie is invalid (sub claim not found)");
        return None;
    };

    let Some(sub) = sub.as_str() else {
        log::debug!(target: LOG_TARGET, "Session cookie is invalid (sub claim is not string)");
        return None;
    };

    let claims = token_payload
        .iter()
        .filter_map(|p| p.1.as_str().map(|v| (p.0.clone(), v.to_string())))
        .collect::<HashMap<String, String>>();

    return Some(SessionCookie {
        sub: sub.to_string(),
        claims,
        domain: cookie.domain().map(|d| d.to_string()),
        is_secure: cookie.secure().unwrap_or_default(),
    });
}
