//// This module aims to fulfill most of [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750) for attaching an access token to an HTTP request to a protected resource.

import flwr_oauth2/common
import flwr_oauth2/http_headers
import flwr_oauth2/response
import flwr_oauth2/token_request
import flwr_oauth2/www_authenticate_parser.{type Challenge}
import gleam/http/request
import gleam/http/response.{type Response} as _
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

/// Attach the access token to the `Authorization` header as Bearer token.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1).
pub fn attach_bearer_token_header(
  req: request.Request(a),
  token: response.AccessTokenResponse,
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
  req: token_request.UrlEncRequest,
  token: response.AccessTokenResponse,
) -> token_request.UrlEncRequest {
  attach_access_token_string_to_body(req, token.access_token)
}

/// See [attach_access_token_to_body](#attach_access_token_to_body)
pub fn attach_access_token_string_to_body(
  req: token_request.UrlEncRequest,
  access_token: String,
) -> token_request.UrlEncRequest {
  req.body
  |> list.prepend(access_token_tuple(access_token))
  |> request.set_body(req, _)
}

/// Attach the access token to the query parameters as access token.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.3).
pub fn attach_access_token_to_query_parameters(
  req: request.Request(a),
  token: response.AccessTokenResponse,
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

pub type BearerErrorResponse {
  BearerErrorResponse(
    realm: option.Option(String),
    scope: common.Scope,
    error: option.Option(String),
    error_description: option.Option(String),
    error_uri: option.Option(uri.Uri),
  )
}

/// This method implements [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-3) to parse error responses.
/// Use this method when requesting a resource from the resource server and it responds with 401 status code.
/// Per RFC6750 when the server responds with 401, the bearer token must not be reused, even if there is no BearerErrorResponse.
pub fn parse_bearer_error_response(
  response resp: Response(a),
) -> Result(List(BearerErrorResponse), Nil) {
  let challenges =
    resp.headers
    |> list.filter(fn(el) { string.lowercase(el.0) == "www-authenticate" })
    |> list.map(fn(h) { www_authenticate_parser.parse(h.1) })
    |> result.all()
    |> result.map(list.flatten)
    |> result.replace_error(Nil)
  use challenges <- result.map(challenges)
  challenges
  |> list.filter(fn(c) { string.lowercase(c.scheme) == "bearer" })
  |> list.map(parse_challenge)
}

fn parse_challenge(challenge: Challenge) {
  let params =
    challenge.parameters
    |> list.map(fn(c) { #(string.lowercase(c.0), c.1) })
  let realm = params |> list.key_find("realm") |> option.from_result()
  let scope =
    params
    |> list.key_find("scope")
    |> result.map(common.parse_scope)
    |> option.from_result()
    |> option.unwrap([])
  let error = params |> list.key_find("error") |> option.from_result()
  let error_description =
    params |> list.key_find("error_description") |> option.from_result()
  let error_uri =
    params
    |> list.key_find("error_uri")
    |> result.try(uri.parse)
    |> option.from_result()
  BearerErrorResponse(realm:, scope:, error:, error_description:, error_uri:)
}
