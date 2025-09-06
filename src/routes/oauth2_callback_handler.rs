use actix_session::SessionExt;
use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use serde::Deserialize;

const LOG_TARGET: &str = "traefik_auth::handler::oauth2_callback";

#[derive(Deserialize)]
pub struct Query {
    error: Option<String>,
    state: Option<String>,
    code: Option<String>,
    iss: Option<String>,
}

#[get("/oauth2/callback")]
pub(crate) async fn handler(req: HttpRequest, query: web::Query<Query>) -> impl Responder {
    let session = req.get_session();
    let csrf_token = session
        .get::<String>("oauth2:csrf_token")
        .unwrap_or_default();

    let Some(csrf_token) = csrf_token else {
        log::debug!(target: LOG_TARGET, "Could not find CSRF Token in session");
        return HttpResponse::Unauthorized().finish();
    };

    if query.state.is_none() {
        return HttpResponse::BadRequest().body("Missing state parameter");
    }

    if *query.state.as_ref().unwrap() != csrf_token {
        log::warn!(target: LOG_TARGET, "Received state {0} but expected {csrf_token}", query.state.as_ref().unwrap());
        return HttpResponse::BadRequest().body("Invalid state value");
    }

    if query.error.is_some() {
        return HttpResponse::InternalServerError().body(format!(
            "Login request failed: {}",
            query.error.clone().unwrap()
        ));
    }

    session.remove("oauth2:csrf_token");
    let Some(code) = &query.code else {
        return HttpResponse::BadRequest().body("Missing code parameter");
    };

    session.insert("oauth2:token", code).expect("bum");
    if query.iss.is_some() {
        session
            .insert("oauth2:iss", query.iss.as_ref().unwrap())
            .expect("bum");
    }

    match session.get::<String>("auth:redirect_uri").expect("bum") {
        Some(redirect_uri) => {
            log::debug!(target: LOG_TARGET, "Redirecting to {redirect_uri}");
            session.remove("auth:redirect_uri");
            HttpResponse::TemporaryRedirect()
                .append_header(("Location", redirect_uri))
                .finish()
        }
        _ => {
            log::debug!(target: LOG_TARGET, "Redirecting to /auth");
            HttpResponse::TemporaryRedirect()
                .append_header(("Location", "/auth"))
                .finish()
        }
    }
}
