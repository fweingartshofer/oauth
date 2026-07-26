import flwr_oauth2/authentication.{type ClientAuthentication}
import flwr_oauth2/common
import flwr_oauth2/helpers
import flwr_oauth2/http_headers
import gleam/bool
import gleam/http
import gleam/http/request.{type Request}
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

/// The essential requests of OAuth 2.0.
/// The token requests includes all the different Grant Types defined in [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
pub type TokenRequest {
  /// A token request for the Authorization Code Grant Type.
  /// Use the [`AuthorizationCodeGrantRedirectUri`](#AuthorizationCodeGrantRedirectUri) to retrieve the `code`.
  /// See [RFC6749 Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).
  AuthorizationCodeGrantTokenRequest(
    token_endpoint: uri.Uri,
    authentication: ClientAuthentication,
    redirect_uri: option.Option(uri.Uri),
    code: String,
  )
  /// A token request for the Resource Owner Password Grant Type.
  /// See [RFC6749 Resource Owner Password Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3).
  ResourceOwnerCredentialsGrantTokenRequest(
    token_endpoint: uri.Uri,
    authentication: ClientAuthentication,
    username: String,
    password: String,
    scope: common.Scope,
  )
  /// This token request is used to refresh an expired access token.
  /// After a successful token request, the OAuth 2.0 Server can respond with an access token and/or a refresh token.
  /// The refresh token can be used to get a new access token.
  /// See [RFC6749 Refreshing an Access Token](https://datatracker.ietf.org/doc/html/rfc6749#section-6).
  RefreshTokenGrantRequest(
    token_endpoint: uri.Uri,
    authentication: ClientAuthentication,
    refresh_token: String,
    scope: common.Scope,
  )
  /// This token request is used to retrieve an access token using the client id and client secret.
  /// See [RFC6749 Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4).
  ClientCredentialsGrantTokenRequest(
    token_endpoint: uri.Uri,
    authentication: ClientAuthentication,
    scope: common.Scope,
  )
}

/// Errors returned by this module when creating requests
pub type RequestError {
  /// Will be returned if an expired secret is used.
  SecretExpired
  /// Will be returned if an invalid URL is provided
  InvalidUri
}

/// Type alias for URL encoded http requests.
pub type UrlEncRequest =
  Request(List(#(String, String)))

/// Type for functions that can set the authorization part of a request.
/// Can be used to customize how authorization is applied to an OAuth request.
pub type AuthorizationSetter {
  AuthorizationSetter(
    setter: fn(UrlEncRequest) -> Result(UrlEncRequest, RequestError),
  )
}

pub type RequestModifier =
  fn(UrlEncRequest) -> Result(UrlEncRequest, RequestError)

pub fn to_string(req: TokenRequest) {
  let auth = authentication.to_string(req.authentication)
  case req {
    AuthorizationCodeGrantTokenRequest(
      token_endpoint:,
      redirect_uri:,
      code:,
      ..,
    ) ->
      "AuthorizationCodeGrantTokenRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> auth
      <> ", "
      <> "redirect_uri="
      <> option.map(redirect_uri, uri.to_string)
      |> option.unwrap("None")
      <> ", "
      <> "code="
      <> code
      <> ")"

    ResourceOwnerCredentialsGrantTokenRequest(
      token_endpoint:,
      username:,
      password:,
      scope:,
      ..,
    ) ->
      "ResourceOwnerCredentialsGrantTokenRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> auth
      <> ", "
      <> "username="
      <> username
      <> ", "
      <> "password="
      <> password
      <> ", "
      <> "scope="
      <> string.join(scope, " ")
      <> ")"

    RefreshTokenGrantRequest(token_endpoint:, refresh_token:, scope:, ..) ->
      "RefreshTokenGrantRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> auth
      <> ", "
      <> "refresh_token="
      <> refresh_token
      <> ", "
      <> "scope="
      <> string.join(scope, " ")
      <> ")"

    ClientCredentialsGrantTokenRequest(token_endpoint:, scope:, ..) ->
      "ClientCredentialsGrantTokenRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> auth
      <> ", "
      <> "scope="
      <> string.join(scope, " ")
      <> ")"
  }
}

/// Creates a http request from the given TokenRequest applying the given modifiers, but does not send it.
/// Sending the request is done by the user of the function.
pub fn to_http_request(request) {
  request |> to_http_request_with_modifiers([])
}

/// Creates a http request from the given TokenRequest applying the given modifiers, but does not send it.
/// Sending the request is done by the user of the function.
pub fn to_http_request_with_modifiers(
  request: TokenRequest,
  modifiers: List(RequestModifier),
) -> Result(Request(String), RequestError) {
  let modifiers = [authorization_setter(request.authentication), ..modifiers]
  base_http_request(request)
  |> result.try(apply_modifiers(_, modifiers))
  |> result.map(request_body_to_string)
}

pub fn to_http_request_with_custom_authentication(
  request: TokenRequest,
  modifiers: List(RequestModifier),
) {
  base_http_request(request)
  |> result.try(apply_modifiers(_, modifiers))
  |> result.map(request_body_to_string)
}

fn base_http_request(req: TokenRequest) -> Result(UrlEncRequest, RequestError) {
  request_body(req)
  |> setup_request(endpoint: req.token_endpoint, body: _)
}

fn request_body(request: TokenRequest) -> List(#(String, String)) {
  case request {
    AuthorizationCodeGrantTokenRequest(redirect_uri:, code:, ..) -> {
      let redirect_uri = helpers.encode_redirect_uri(redirect_uri)
      [#("grant_type", "authorization_code"), #("code", code)]
      |> helpers.add_if_present(redirect_uri)
    }
    ResourceOwnerCredentialsGrantTokenRequest(username:, password:, scope:, ..) -> {
      [
        #("grant_type", "password"),
        #("username", username),
        #("password", password),
      ]
      |> add_scope(scope)
    }
    RefreshTokenGrantRequest(refresh_token:, scope:, ..) -> {
      [#("grant_type", "refresh_token"), #("refresh_token", refresh_token)]
      |> add_scope(scope)
    }
    ClientCredentialsGrantTokenRequest(scope:, ..) -> {
      [
        #("grant_type", "client_credentials"),
      ]
      |> add_scope(scope)
    }
  }
}

pub fn apply_modifiers(
  request: UrlEncRequest,
  modifiers: List(RequestModifier),
) -> Result(UrlEncRequest, RequestError) {
  list.fold(over: modifiers, from: Ok(request), with: result.try)
}

pub fn request_body_to_string(
  request: UrlEncRequest,
) -> request.Request(String) {
  request.body
  |> uri.query_to_string()
  |> request.set_body(request, _)
}

/// Function that adds a scope to a list if the scope is not empty.
fn add_scope(
  d: List(#(String, String)),
  scope: common.Scope,
) -> List(#(String, String)) {
  case scope {
    [_, ..] as scope -> option.Some(#("scope", scope |> string.join(" ")))
    _ -> option.None
  }
  |> helpers.add_if_present(d, _)
}

/// A helper function that maps a general request with credentials to a gleam http request.
/// The credentials are either attached to the request body URL encoded or added as basic `authorization` header.
pub fn setup_request(
  endpoint endpoint: uri.Uri,
  body body: List(#(String, String)),
) -> Result(Request(List(#(String, String))), RequestError) {
  let req =
    request.from_uri(endpoint)
    |> result.replace_error(InvalidUri)
  use req <- result.try(req)
  req
  |> request.set_method(http.Post)
  |> request.set_header("content-type", "application/x-www-form-urlencoded")
  |> request.set_body(body)
  |> Ok
}

/// Encodes the ClientAuthentication that is to be sent to the OAuth 2.0 Server.
/// For Basic Authentication it will always encode it with base64.
pub fn authorization_setter(auth: ClientAuthentication) -> RequestModifier {
  case auth {
    authentication.ClientSecretBasic(client_id, client_secret) ->
      compose(
        guard_secret(client_secret),
        set_basic_header(client_id.value, client_secret.value),
      )
    authentication.ClientSecretPost(client_id, client_secret) ->
      compose(
        guard_secret(client_secret),
        add_body([
          #("client_id", client_id.value),
          #("client_secret", client_secret.value),
        ]),
      )
    authentication.PublicAuthentication(client_id) ->
      add_body([
        #("client_id", client_id.value),
      ])
    authentication.ClientAssertion(
      client_id,
      client_assertion,
      client_assertion_type,
    ) ->
      add_body([
        #("client_id", client_id.value),
        #("client_assertion_type", client_assertion_type),
        #("client_assertion", client_assertion),
      ])
  }
}

fn compose(first: RequestModifier, second: RequestModifier) -> RequestModifier {
  fn(req: UrlEncRequest) {
    req
    |> first
    |> result.try(second)
  }
}

fn guard_secret(secret: common.Secret) -> RequestModifier {
  fn(req: UrlEncRequest) {
    use <- bool.guard(
      when: common.is_secret_invalid(secret),
      return: Error(SecretExpired),
    )
    Ok(req)
  }
}

fn add_body(fields: List(#(String, String))) -> RequestModifier {
  fn(req: UrlEncRequest) {
    req.body
    |> list.append(fields, _)
    |> request.set_body(req, _)
    |> Ok
  }
}

fn set_basic_header(
  client_id: String,
  client_secret: String,
) -> RequestModifier {
  fn(req: UrlEncRequest) {
    req
    |> http_headers.set_basic(client_id, client_secret)
    |> Ok
  }
}

/// Build a POST request for an OAuth 2.0 endpoint with the given form-encoded body,
/// authentication, and optional modifiers.
/// This is a lower-level alternative to [`to_http_request_with_modifiers`] that
/// does not require a [`TokenRequest`] type — useful for modules that need to
/// construct requests with custom body content (e.g., revocation, assertion grants).
pub fn build_post_request(
  endpoint: uri.Uri,
  body: List(#(String, String)),
  authentication: ClientAuthentication,
  modifiers: List(RequestModifier),
) -> Result(Request(String), RequestError) {
  let modifiers = [authorization_setter(authentication), ..modifiers]
  setup_request(endpoint, body)
  |> result.try(apply_modifiers(_, modifiers))
  |> result.map(request_body_to_string)
}
