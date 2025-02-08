use std::{error::Error, fmt::Display, future::Future, pin::Pin};

use actix_web::error::PayloadError;
use awc::{Client, error::SendRequestError};
use oauth2::{http::{header::InvalidHeaderValue, HeaderValue, Response}, AsyncHttpClient, HttpRequest, HttpResponse};

#[derive(Debug)]
pub(crate) enum OAuth2HttpError {
    RequestError(SendRequestError),
    ResponseError(PayloadError),
    ResponseHeaderError(InvalidHeaderValue),
    ResponseHttpError(oauth2::http::Error),
}

pub(crate) struct OAuth2HttpClient {}

impl Default for OAuth2HttpClient {
    fn default() -> Self {
        Self {}
    }
}

impl<'c> AsyncHttpClient<'c> for OAuth2HttpClient {
    type Error = OAuth2HttpError;

    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let client = Client::builder()
                .disable_redirects()
                .finish();

            let mut awc_request = match request.method().as_str() {
                "GET" => client.get(request.uri().to_string()),
                "POST" => client.post(request.uri().to_string()),
                _ => client.get(request.uri().to_string()),
            };

            for (key, value) in request.headers().iter() {
                awc_request = awc_request.append_header((key.as_str(), value.as_bytes()));
            }

            let request_body = request.body().clone();
            let mut awc_response = if request_body.is_empty() {
                awc_request.send()
            } else {
                awc_request.send_body(request_body)
            }.await?;

            let mut builder = Response::builder()
                .status(awc_response.status().as_u16());
            for (key, value) in awc_response.headers().iter() {
                let header_value = HeaderValue::from_bytes(value.as_bytes())?;
                builder = builder.header(key.as_str(), header_value);
            }

            builder
                .body(awc_response.body().await?.to_vec())
                .map_err(OAuth2HttpError::ResponseHttpError)
        })
    }
}

impl Display for OAuth2HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestError(err) => write!(f, "Request Error: {err}"),
            Self::ResponseError(err) => write!(f, "Response Error: {err}"),
            Self::ResponseHeaderError(err) => write!(f, "Response header Error: {err}"),
            Self::ResponseHttpError(err) => write!(f, "Response HTTP Error: {err}"),
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
