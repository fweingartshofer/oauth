//// This module implements [RFC7662 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662).
//// It allows the protected resource to introspect a presented token.

import flwr_oauth2/bearer_token
import flwr_oauth2/common.{type ClientId, type Scope, ClientId}
import flwr_oauth2/helpers
import flwr_oauth2/response
import flwr_oauth2/revocation
import flwr_oauth2/token_request
import gleam/dynamic/decode
import gleam/http/request
import gleam/http/response.{type Response} as _
import gleam/json
import gleam/list
import gleam/option.{type Option, None}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gleam/uri

pub type IntrospectionRequest {
  IntrospectionRequest(
    endpoint: uri.Uri,
    token: String,
    token_hint: Option(revocation.TokenTypeHint),
  )
}

fn introspection_request_to_form_encoded(
  introspection_request: IntrospectionRequest,
) -> List(#(String, String)) {
  let IntrospectionRequest(token:, token_hint:, ..) = introspection_request
  let token_hint =
    token_hint
    |> option.map(revocation.token_type_hint_to_string)
    |> option.map(fn(x) { #("token_type_hint", x) })
  [#("token", token)]
  |> helpers.add_if_present(token_hint)
}

/// Implements the token introspection request according to [RFC7662](https://datatracker.ietf.org/doc/html/rfc7662).
/// Needs to be combined either with [the basic authentication](./authentication.html#basic_authenticate_http_request) or [an bearer token](./bearer_token.html).
/// To attach an access token see the example below:
///
/// ```gleam
/// import flwr_oauth2/bearer_token
/// import flwr_oauth2/token_introspection.{IntrospectionRequest}
/// import flwr_oauth2/revocation.{AccessToken}
/// let intro_req =
///   IntrospectionRequest(
///     endpoint: todo as "define endpoint",
///     token: todo as "define token",
///     token_hint: todo as "add token hint if known/required",
///   )
/// let req =
///   to_http_request(intro_req)
///   |> result.map(bearer_token.attach_bearer_token_string_to_header(
///     _,
///     "access-token",
///   ))
/// ```
pub fn to_http_request(
  introspection_request: IntrospectionRequest,
) -> Result(request.Request(String), token_request.RequestError) {
  to_http_request_with_extensions(introspection_request, [])
}

/// Same as [to_http_request](#to_http_request), but allows custom extension to be added to the request body
/// Allows extensions to the body, which are not checked for duplicated or protected attributes.
pub fn to_http_request_with_extensions(
  introspection_request: IntrospectionRequest,
  extensions: List(#(String, String)),
) -> Result(request.Request(String), token_request.RequestError) {
  token_request.setup_request(
    endpoint: introspection_request.endpoint,
    body: introspection_request_to_form_encoded(introspection_request)
      |> list.append(extensions),
  )
  |> result.map(token_request.request_body_to_string)
  |> result.map(request.set_header(_, "accept", "application/json"))
}

pub type IntrospectionResponse {
  IntrospectionResponse(
    active: Bool,
    scope: Scope,
    client_id: Option(ClientId),
    username: Option(String),
    token_type: Option(String),
    expires_at: Option(Timestamp),
    issued_at: Option(Timestamp),
    not_before: Option(Timestamp),
    subject: Option(String),
    audience: List(String),
    issuer: Option(String),
    jti: Option(String),
  )
}

/// The error types that can occur when parsing the response from the token introspection endpoint.
pub type IntrospectionErrorResponse {
  /// The client that is used to authorize the request could not be used for authorization.
  AuthorizationServerError(response.AuthorizationServerError)
  /// The bearer token used to authorize the request could not be used for authorization.
  BearerTokenError(List(bearer_token.BearerErrorResponse))
  /// The response uses a status code not listed in RFC 7662.
  InvalidStatus(status: Int)
  /// This error indicates that the response contains a response format error, such as an invalid content-type or JSON parse error.
  ParseError(common.ParseError)
  /// Parsing the `WWW-Authenticate` header led to an parsing error.
  BearerTokenParseError(bearer_token.BearerTokenParserError)
}

/// Parses the [RFC7662 Responses and Error Responses](https://datatracker.ietf.org/doc/html/rfc7662).
/// If the error response code is 401, it will try to parse the `WWW-Authenticate` header first.
/// If it does not contain any errors regarding a bearer token, it will try to parse the response body.
/// Assumes that a missing content type for a success response means that the response contains a JSON body.
pub fn parse_introspection_response(
  response resp: Response(String),
) -> Result(IntrospectionResponse, IntrospectionErrorResponse) {
  let json_response = resp |> helpers.verify_content_type("application/json")
  case resp.status, json_response {
    200, Ok(_) | 200, Error(helpers.MissingContentType) ->
      json.parse(resp.body, introspection_response_decoder())
      |> result.map_error(common.ParseError)
      |> result.map_error(ParseError)
    401, _ -> parse_error_response(resp, json_response)
    _, Error(helpers.OtherContentType(ct)) ->
      common.UnsupportedContent(ct) |> ParseError |> Error
    status, _ -> InvalidStatus(status) |> Error
  }
}

fn parse_error_response(
  resp: Response(String),
  is_json: Result(Nil, helpers.ContentTypeError),
) -> Result(c, IntrospectionErrorResponse) {
  case bearer_token.parse_bearer_error_response(resp), is_json {
    Error(bearer_token.MissingBearerError), Ok(_) ->
      response.parse_error_response(resp)
      |> result.map_error(ParseError)
      |> result.map(AuthorizationServerError)
      |> helpers.unwrap_both()
      |> Error
    Ok(bearer_error), _ -> bearer_error |> BearerTokenError |> Error
    Error(error), _ -> error |> BearerTokenParseError |> Error
  }
}

fn introspection_response_decoder() -> decode.Decoder(IntrospectionResponse) {
  use active <- decode.field("active", decode.bool)
  use scope <- decode.optional_field(
    "scope",
    None,
    decode.optional(decode.string),
  )
  let scope = scope |> option.map(common.parse_scope) |> option.unwrap([])
  use client_id <- decode.optional_field(
    "client_id",
    None,
    decode.optional(decode.string),
  )
  let client_id = client_id |> option.map(ClientId)
  use username <- decode.optional_field(
    "username",
    None,
    decode.optional(decode.string),
  )
  use token_type <- decode.optional_field(
    "token_type",
    None,
    decode.optional(decode.string),
  )
  use expires_at <- decode.optional_field(
    "exp",
    None,
    decode.optional(common.timestamp_decoder()),
  )
  use issued_at <- decode.optional_field(
    "iat",
    None,
    decode.optional(common.timestamp_decoder()),
  )
  use not_before <- decode.optional_field(
    "nbf",
    None,
    decode.optional(common.timestamp_decoder()),
  )
  use subject <- decode.optional_field(
    "sub",
    None,
    decode.optional(decode.string),
  )
  use audience <- decode.optional_field(
    "aud",
    None,
    decode.optional(
      decode.one_of(decode.then(decode.string, fn(x) { decode.success([x]) }), [
        decode.list(decode.string),
      ]),
    ),
  )
  let audience = audience |> option.unwrap([])
  use issuer <- decode.optional_field(
    "iss",
    None,
    decode.optional(decode.string),
  )
  use jti <- decode.optional_field("jti", None, decode.optional(decode.string))
  decode.success(IntrospectionResponse(
    active:,
    scope:,
    client_id:,
    username:,
    token_type:,
    expires_at:,
    issued_at:,
    not_before:,
    subject:,
    audience:,
    issuer:,
    jti:,
  ))
}
