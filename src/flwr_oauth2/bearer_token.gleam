//// This module aims to fulfill most of [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750) for attaching an access token to an HTTP request to a protected resource.

import flwr_oauth2 as oauth
import flwr_oauth2/http_headers
import gleam/http/request
import gleam/list

/// Attach the access token to the `Authorization` header as Bearer token.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1).
pub fn attach_bearer_token_header(
  req: request.Request(a),
  token: oauth.AccessTokenResponse,
) -> request.Request(a) {
  attach_bearer_token_string_to_header(req, token.access_token)
}

/// See [attach_bearer_token_header](#attach_bearer_token_header)
pub fn attach_bearer_token_string_to_header(
  req: request.Request(a),
  access_token: String,
) -> request.Request(a) {
  http_headers.set_bearer(req, access_token)
}

/// Attach the access token to the body as access token.
/// This function adds the access token to the body of provided request.
/// It does not set the content type to `application/x-www-form-urlencoded`, but in order to send the body with the access token to a server it has to be set and the body needs to be url encoded.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.2).
pub fn attach_access_token_to_body(
  req: oauth.UrlEncRequest,
  token: oauth.AccessTokenResponse,
) -> oauth.UrlEncRequest {
  attach_access_token_string_to_body(req, token.access_token)
}

/// See [attach_access_token_to_body](#attach_access_token_to_body)
pub fn attach_access_token_string_to_body(
  req: oauth.UrlEncRequest,
  access_token: String,
) -> oauth.UrlEncRequest {
  req.body
  |> list.prepend(access_token_tuple(access_token))
  |> request.set_body(req, _)
}

/// Attach the access token to the query parameters as access token.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.3).
pub fn attach_access_token_to_query_parameters(
  req: request.Request(a),
  token: oauth.AccessTokenResponse,
) -> request.Request(a) {
  attach_access_token_string_to_query_parameters(req, token.access_token)
}

/// See [attach_access_token_to_query_parameters](#attach_access_token_to_query_parameters)
pub fn attach_access_token_string_to_query_parameters(
  req: request.Request(a),
  access_token: String,
) -> request.Request(a) {
  case request.get_query(req) {
    Error(_) -> []
    Ok(query_params) -> query_params
  }
  |> list.prepend(access_token_tuple(access_token))
  |> request.set_query(req, _)
}

fn access_token_tuple(token: String) -> #(String, String) {
  #("access_token", token)
}
