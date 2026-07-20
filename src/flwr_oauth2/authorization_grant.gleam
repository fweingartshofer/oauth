import flwr_oauth2.{
  type AccessTokenResponse, type ClientId, type Scope, AccessTokenResponse,
  AuthorizationCodeGrantTokenRequest,
}
import flwr_oauth2/helpers
import flwr_oauth2/pkce
import gleam/dict
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option.{Some}
import gleam/result
import gleam/string
import gleam/uri

/// Type to indicate the state.
/// Mostly used to have type-safe parameters, so other string parameters are not mixed up.
/// See [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
pub type State {
  State(value: String)
}

/// Type to indicate the response type of the authorization code and implicit grant.
/// Must always be "code" for the authorizatin code grant and alway be "token" for the implicit grant.
/// For more information see [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1).
pub type ResponseType {
  Code
  Token
}

/// The kind of code challenge method used for the PKCE extension.
/// See [RFC7636 Client Creates Code Challenge](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2)
pub type CodeChallengeMethod {
  Plain
  S256
}

/// This defines a redirect url defined by [RFC6749 Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).
pub type AuthorizationCodeGrantRequest {
  /// Represents a redirect url with an optional PKCE code challenge.
  /// See [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636).
  AuthorizationCodeGrantRequest(
    authorization_endpoint: uri.Uri,
    response_type: ResponseType,
    redirect_uri: option.Option(uri.Uri),
    client_id: ClientId,
    scope: Scope,
    state: option.Option(State),
    code_challenge: option.Option(String),
    code_challenge_method: option.Option(CodeChallengeMethod),
  )
}

/// Parsed response when the authorization server redirects back to the caller using the given redirect URI.
/// See [Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2)
pub type AuthorizationResponse {
  ImplicitGrantResponse(state: option.Option(State), token: AccessTokenResponse)
  CodeGrantResponse(state: option.Option(State), code: String)
  ErrorResponse(
    state: option.Option(State),
    error: String,
    error_description: option.Option(String),
    error_uri: option.Option(uri.Uri),
  )
}

pub type ParseError {
  /// Error when a required field is not present on the Authorization Response or the query parameters could not be parsed
  ParseError(field: option.Option(String))
}

/// Creates a String representation of the AuthorizationResponse
pub fn to_string(resp: AuthorizationResponse) {
  let state =
    resp.state |> option.map(fn(s) { s.value }) |> option.unwrap("None")
  case resp {
    ImplicitGrantResponse(token:, state: _) -> {
      let token_response = flwr_oauth2.to_string_token_response(token)
      "ImplicitGrantResponse(
  token: " <> token_response <> ",
  state: " <> state <> "
)"
    }
    CodeGrantResponse(code:, state: _) -> {
      "CodeGrantResponse(code: " <> code <> ", state: " <> state <> ")"
    }
    ErrorResponse(error:, error_description:, error_uri:, state: _) -> {
      let error_description = error_description |> option.unwrap("None")
      let error_uri =
        error_uri
        |> option.map(uri.to_string)
        |> option.unwrap("None")
      "ErrorResponse(
        error: " <> error <> ",
        error_description: " <> error_description <> ",
        error_uri: " <> error_uri <> ",
        state: " <> state <> "
      )"
    }
  }
}

pub fn error_to_string(error: ParseError) -> String {
  let field = error.field |> option.unwrap("None")
  "ParseError(field: " <> field <> ")"
}

/// Creates a new Authorization Code Grant Request, with empty fields.
/// Mostly a convenience function, watch out for empty values!
pub fn new() -> AuthorizationCodeGrantRequest {
  AuthorizationCodeGrantRequest(
    authorization_endpoint: uri.empty,
    response_type: Token,
    redirect_uri: option.None,
    client_id: flwr_oauth2.ClientId(""),
    scope: [],
    state: option.None,
    code_challenge: option.None,
    code_challenge_method: option.None,
  )
}

pub fn set_authorization_endpoint(
  req: AuthorizationCodeGrantRequest,
  authorization_endpoint: uri.Uri,
) {
  AuthorizationCodeGrantRequest(..req, authorization_endpoint:)
}

pub fn set_response_type(
  req: AuthorizationCodeGrantRequest,
  response_type: ResponseType,
) {
  AuthorizationCodeGrantRequest(..req, response_type:)
}

pub fn set_redirect_uri(
  req: AuthorizationCodeGrantRequest,
  redirect_uri: uri.Uri,
) {
  AuthorizationCodeGrantRequest(..req, redirect_uri: Some(redirect_uri))
}

pub fn set_client_id(req: AuthorizationCodeGrantRequest, client_id: ClientId) {
  AuthorizationCodeGrantRequest(..req, client_id:)
}

pub fn set_scope(req: AuthorizationCodeGrantRequest, scope: Scope) {
  AuthorizationCodeGrantRequest(..req, scope:)
}

pub fn set_state(req: AuthorizationCodeGrantRequest, state: State) {
  AuthorizationCodeGrantRequest(..req, state: Some(state))
}

pub fn set_code_challenge(
  req: AuthorizationCodeGrantRequest,
  code_challenge: String,
  code_challenge_method: CodeChallengeMethod,
) {
  AuthorizationCodeGrantRequest(
    ..req,
    code_challenge: Some(code_challenge),
    code_challenge_method: Some(code_challenge_method),
  )
}

/// Creates the uri that the resource owner should be redirected too.
pub fn make_redirect_uri(
  redirect_config: AuthorizationCodeGrantRequest,
) -> uri.Uri {
  let state =
    redirect_config.state
    |> option.map(fn(x) { x.value })
    |> option.map(helpers.wrap_tuple("state", _))
  let redirect_uri = helpers.encode_redirect_uri(redirect_config.redirect_uri)
  let code_challenge =
    redirect_config.code_challenge
    |> option.map(helpers.wrap_tuple("code_challenge", _))
  let code_challenge_method =
    redirect_config.code_challenge_method
    |> option.map(fn(x) {
      #("code_challenge_method", case x {
        Plain -> "plain"
        S256 -> "S256"
      })
    })
  let queries =
    [
      #("response_type", response_type_to_string(redirect_config.response_type)),
      #("client_id", redirect_config.client_id.value),
      #("scope", string.join(redirect_config.scope, " ")),
    ]
    |> helpers.add_if_present(redirect_uri)
    |> helpers.add_if_present(state)
    |> helpers.add_if_present(code_challenge_method)
    |> helpers.add_if_present(code_challenge)
  uri.Uri(
    ..redirect_config.authorization_endpoint,
    query: Some(uri.query_to_string(queries)),
  )
}

/// Parses the authorization code response from the query parameters of an HTTP request.
/// This handles the Authorization Code Grant per [Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2).
/// For the Implicit Grant, use [`parse_authorization_response_for_implicit_grant`](#parse_authorization_response_for_implicit_grant)
/// since parameters are in the fragment component per [Section 4.2.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2).
pub fn parse_authorization_response_for_code_grant(
  req: request.Request(_),
) -> Result(AuthorizationResponse, ParseError) {
  req.query
  |> parse_authorization_response_url_form_encoded()
}

/// Parses the redirect URI from the authorization server response.
/// For the Authorization Code Grant (RFC6749 §4.1.2), parameters are in the query component.
/// For the Implicit Grant (RFC6749 §4.2.2), parameters are in the fragment component.
pub fn parse_authorization_response_for_implicit_grant(
  uri: uri.Uri,
) -> Result(AuthorizationResponse, ParseError) {
  uri.fragment
  |> parse_authorization_response_url_form_encoded()
}

fn parse_authorization_response_url_form_encoded(
  url_encoded_response: option.Option(String),
) -> Result(AuthorizationResponse, ParseError) {
  let payload =
    url_encoded_response
    |> option.map(uri.parse_query)
    |> option.to_result(Nil)
    |> result.flatten()
    |> result.map_error(fn(_) { ParseError(option.None) })
    |> result.map(fn(d) {
      case list.is_empty(d) {
        True -> Error(ParseError(option.None))
        False -> Ok(d)
      }
    })
    |> result.flatten
  use pairs <- result.try(payload)
  let query = pairs |> dict.from_list()
  parse_authorization_response_query(query)
}

/// Parses the query from the authorization response HTTP request.
/// This function is intended to be used in case your implementation does not use the standard gleam/http/request type.
pub fn parse_authorization_response_query(
  query: dict.Dict(String, String),
) -> Result(AuthorizationResponse, ParseError) {
  let error_response = parse_error_response(query)
  use error_response <- result.try(error_response)
  let error_response = error_response |> option.map(Ok)
  use <- option.lazy_unwrap(error_response)
  let code_response = parse_authorization_code_response(query)
  // If no code is present, this might be an implicit authorization flow
  use _ <- result.try_recover(code_response)
  parse_authorization_implicit_response(query)
}

fn parse_authorization_code_response(
  query: dict.Dict(String, String),
) -> Result(AuthorizationResponse, ParseError) {
  use code <- parse_required_field(query, "code")
  let state =
    query
    |> parse_optional_field("state")
    |> option.map(State)
  Ok(CodeGrantResponse(code:, state:))
}

fn parse_authorization_implicit_response(
  query: dict.Dict(String, String),
) -> Result(AuthorizationResponse, ParseError) {
  use access_token <- parse_required_field(query, "access_token")
  use token_type <- parse_required_field(query, "token_type")
  let expires_in =
    query
    |> parse_optional_field("expires_in")
    |> option.map(int.parse)
    |> option.map(fn(res) { result.map(res, option.Some) })
    |> option.unwrap(Ok(option.None))
    |> create_parse_error("expires_in")
  use expires_in <- result.try(expires_in)

  let scope =
    query
    |> parse_optional_field("scope")
    |> option.map(flwr_oauth2.parse_scope)
    |> option.unwrap([])

  let state =
    query
    |> dict.get("state")
    |> option.from_result()
    |> option.map(State)
  Ok(ImplicitGrantResponse(
    token: AccessTokenResponse(
      access_token: access_token,
      token_type: token_type,
      expires_in: expires_in,
      refresh_token: option.None,
      scope: scope,
    ),
    state: state,
  ))
}

fn parse_error_response(
  query: dict.Dict(String, String),
) -> Result(option.Option(AuthorizationResponse), ParseError) {
  case dict.get(query, "error") {
    Ok(error) -> {
      let error_description = query |> parse_optional_field("error_description")

      let state = query |> parse_optional_field("state") |> option.map(State)
      use error_uri <- parse_optional_uri(query, "error_uri", uri.parse)
      Some(ErrorResponse(error:, error_description:, error_uri:, state:))
    }
    Error(_) -> {
      Ok(option.None)
    }
  }
}

fn parse_optional_uri(
  query: dict.Dict(String, String),
  key: String,
  parser: fn(String) -> Result(a, e),
  apply: fn(option.Option(a)) -> b,
) -> Result(b, ParseError) {
  case dict.get(query, key) {
    Error(_) -> Ok(apply(option.None))
    Ok(value) -> {
      let value = parser(value) |> create_parse_error(key)
      use parsed <- result.try(value)
      Ok(apply(Some(parsed)))
    }
  }
}

fn parse_required_field(
  query: dict.Dict(String, v),
  key: String,
  then: fn(v) -> Result(r, ParseError),
) {
  query
  |> dict.get(key)
  |> create_parse_error(key)
  |> result.try(then)
}

fn parse_optional_field(
  query: dict.Dict(String, v),
  key: String,
) -> option.Option(v) {
  query
  |> dict.get(key)
  |> option.from_result()
}

fn create_parse_error(
  res: Result(a, b),
  field: String,
) -> Result(a, ParseError) {
  res |> result.replace_error(ParseError(Some(field)))
}

/// Utility function to create a TokenRequest from an AuthorizationResponse.
/// If the AuthorizationResponse is an ErrorResponse or an ImplicitGrantResponse returns Error(Nil), otherwise returns an AuthorizationCodeGrantTokenRequest.
pub fn to_token_request(
  authorization_response: AuthorizationResponse,
  token_endpoint: uri.Uri,
  authentication: flwr_oauth2.ClientAuthentication,
  redirect_uri: option.Option(uri.Uri),
) {
  case authorization_response {
    CodeGrantResponse(code:, state: _) -> {
      AuthorizationCodeGrantTokenRequest(
        token_endpoint:,
        authentication:,
        redirect_uri:,
        code:,
      )
      |> Ok
    }
    _ -> Error(Nil)
  }
}

/// Utility function to create a TokenRequest from an AuthorizationResponse.
/// If the AuthorizationResponse is an ErrorResponse or an ImplicitGrantResponse returns Error(Nil), otherwise returns an AuthorizationCodeGrantTokenRequest.
pub fn to_token_request_with_pkce_verifier(
  authorization_response: AuthorizationResponse,
  token_endpoint: uri.Uri,
  authentication: flwr_oauth2.ClientAuthentication,
  redirect_uri: option.Option(uri.Uri),
  verifier: pkce.Verifier,
) {
  case authorization_response {
    CodeGrantResponse(code:, state: _) -> {
      pkce.AuthorizationCodeGrantTokenRequestWithPKCE(
        token_endpoint:,
        authentication:,
        redirect_uri:,
        code:,
        code_verifier: verifier.value,
      )
      |> Ok
    }
    _ -> Error(Nil)
  }
}

const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/// Generates a random State with the specified length including only uppercase and lowercase letters
/// If length <= 0 returns an empty string
pub fn random_state(length: Int) -> State {
  helpers.generate_random_string(chars, length)
  |> State
}

/// Generates a random 32 character long State
pub fn random_state32() -> State {
  random_state(32)
}

fn response_type_to_string(response_type: ResponseType) {
  case response_type {
    Code -> "code"
    Token -> "token"
  }
}
