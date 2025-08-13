use std::collections::HashMap;

use actix_web::{get, web::Data, HttpRequest, HttpResponse, Responder};
use serde::Serialize;

use crate::logic::{cookie::parse_session_cookie, crypto::CryptoState};

const LOG_TARGET: &str = "traefik_auth::handler::me";

#[derive(Serialize)]
struct Me {
    sub: String,
    claims: HashMap<String, String>,
}

#[get("/me")]
pub(crate) async fn handler(
    req: HttpRequest,
    crypto_state: Data<CryptoState>,
) -> impl Responder {
    let Some(cookie) = parse_session_cookie(&req, &crypto_state) else {
        log::debug!(target: LOG_TARGET, "No cookie found");
        return HttpResponse::Unauthorized()
            .finish();
    };

    HttpResponse::Ok().json(Me { sub: cookie.sub, claims: cookie.claims })
}
