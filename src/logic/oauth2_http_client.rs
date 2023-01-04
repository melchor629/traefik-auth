use std::{fmt::Display, error::Error};

use actix_web::{error::PayloadError, http::header::InvalidHeaderValue};
use awc::{Client, error::SendRequestError};
use oauth2::{HttpRequest, HttpResponse, http::{HeaderMap, HeaderValue}};

#[derive(Debug)]
pub(crate) enum OAuth2HttpError {
    RequestError(SendRequestError),
    ResponseError(PayloadError),
    ResponseHeaderError(InvalidHeaderValue),
}

pub(crate) async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, OAuth2HttpError> {
    let client = Client::default();
    let mut awc_request = match request.method.as_str() {
        "GET" => client.get(request.url.as_str()),
        "POST" => client.post(request.url.as_str()),
        _ => client.get(request.url.as_str()),
    };

    for (key, value) in request.headers.iter() {
        awc_request = awc_request.append_header((key, value));
    }

    let mut awc_response = if request.body.len() > 0 {
        awc_request.send_body(request.body)
    } else {
        awc_request.send()
    }.await?;


    let mut response_headers = HeaderMap::new();
    for (key, value) in awc_response.headers().iter() {
        response_headers.append(key, HeaderValue::from_bytes(value.as_bytes())?);
    }

    Ok(HttpResponse {
        body: awc_response.body().await?.to_vec(),
        headers: response_headers,
        status_code: awc_response.status(),
    })
}

impl Display for OAuth2HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestError(err) => write!(f, "Request Error: {err}"),
            Self::ResponseError(err) => write!(f, "Response Error: {err}"),
            Self::ResponseHeaderError(err) => write!(f, "Response header Error: {err}"),
        }
    }
}

impl Error for OAuth2HttpError {}

impl From<SendRequestError> for OAuth2HttpError {
    fn from(value: SendRequestError) -> Self {
        Self::RequestError(value)
    }
}

impl From<PayloadError> for OAuth2HttpError {
    fn from(value: PayloadError) -> Self {
        Self::ResponseError(value)
    }
}

impl From<InvalidHeaderValue> for OAuth2HttpError {
    fn from(value: InvalidHeaderValue) -> Self {
        Self::ResponseHeaderError(value)
    }
}