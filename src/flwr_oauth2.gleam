//// This module implements functions and types for [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
//// It offers types for all the major OAuth 2.0 grant types and functions to create the correct HTTP requests for those grant types.
//// Furthermore, it offers functions to generate redirect URIs for the [Authorization Code Grant Type](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) and the [Implicit Grant Type](https://datatracker.ietf.org/doc/html/rfc6749#section-4.2).
////
//// It also supports [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636), which adds the Proof Key for Code Exchange to the Authorization Code Grant.

import flwr_oauth2/helpers.{add_if_present}
import flwr_oauth2/http_headers
import gleam/bool
import gleam/dynamic/decode
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option
import gleam/order
import gleam/result
import gleam/string
import gleam/time/timestamp
import gleam/uri

/// Type to indicate the client ID.
/// Mostly used to have type-safe parameters, so client id, client secret, etc are not mixed up.
/// See [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
pub type ClientId {
  ClientId(value: String)
}

/// Type to indicate the client secret.
/// Mostly used to have type-safe parameters, so client id, client secret, etc are not mixed up.
/// See [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
pub type Secret {
  /// A normal OAuth 2.0 client secret
  Secret(value: String)
  /// A client secret with an expiration date attached.
  /// Can be used to check if the secret expired.
  SecretWithExpiration(value: String, expires_at: timestamp.Timestamp)
}

/// Type alias for the scope.
/// A scope is a list of strings.
/// See [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
pub type Scope =
  List(String)

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
    scope: Scope,
  )
  /// This token request is used to refresh an expired access token.
  /// After a successful token request, the OAuth 2.0 Server can respond with an access token and/or a refresh token.
  /// The refresh token can be used to get a new access token.
  /// See [RFC6749 Refreshing an Access Token](https://datatracker.ietf.org/doc/html/rfc6749#section-6).
  RefreshTokenGrantRequest(
    token_endpoint: uri.Uri,
    authentication: ClientAuthentication,
    refresh_token: String,
    scope: Scope,
  )
  /// This token request is used to retrieve an access token using the client id and client secret.
  /// See [RFC6749 Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4).
  ClientCredentialsGrantTokenRequest(
    token_endpoint: uri.Uri,
    authentication: ClientAuthentication,
    scope: Scope,
  )
}

/// The type of client authentication that should be used with the OAuth 2.0 Server.
/// An OAuth 2.0 Server can support multiple kinds of client authentication.
/// When the incorrect kind is used, the OAuth 2.0 Server will respond with an error.
/// For the error information see [RFC6749 Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-7.2).
pub type ClientAuthentication {
  /// Use this type if the OAuth 2.0 Server accepts HTTP Basic authentication, which sets the `Authorization` header in the HTTP request.
  /// For example:
  /// ```
  /// Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
  /// ```
  ClientSecretBasic(client_id: ClientId, client_secret: Secret)
  /// Use this type if the OAuth 2.0 Server accepts the credentials via a POST request.
  /// In that case the credentials are sent URL encoded.
  /// For example:
  /// ```
  /// client_id=asdf&client_secret=hjkl
  /// ```
  ClientSecretPost(client_id: ClientId, client_secret: Secret)
  /// Use this type if the client is public and there is no client secret to be included.
  PublicAuthentication(client_id: ClientId)
  /// Use this type if the OAuth 2.0 Server accepts a JWT assertion for client authentication.
  /// See [RFC7523 Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2)
  ClientAssertion(
    client_id: ClientId,
    client_assertion: String,
    client_assertion_type: String,
  )
}

/// Errors returned by this module when creating requests
pub type RequestError {
  /// Will be returned if an expired secret is used.
  SecretExpired
  /// Will be returned if an invalid URL is provided
  InvalidUri
}

/// Errors returned by this module when parsing responses, such as token responses from the OAuth 2.0 server.
pub type ResponseError {
  /// If the response contains errors a `ErrorResponse` will be returned.
  /// It contains the HTTP status, the error code string, optionally an error description and an error URI.
  ErrorResponse(
    status: Int,
    error: String,
    error_description: option.Option(String),
    error_uri: option.Option(String),
  )
  /// If the response does not contain valid JSON or does not conform to the error response format defined by [RFC6749 Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) this error will be returned.
  ParseError(error: json.DecodeError)
}

/// This type is returned by this module for a parsed access token response.
pub type AccessTokenResponse {
  /// If the access token request was successful a `AccessTokenResponse` is returned.
  /// it contains the access token, its type, the time when it will expire, a refresh token if present, and the final scope.
  AccessTokenResponse(
    access_token: String,
    token_type: String,
    expires_in: option.Option(Int),
    refresh_token: option.Option(String),
    scope: Scope,
  )
}

/// Type for functions that can set the authorization part of a request.
/// Can be used to customize how authorization is applied to an OAuth request.
pub type AuthorizationSetter {
  AuthorizationSetter(
    setter: fn(UrlEncRequest) -> Result(UrlEncRequest, RequestError),
  )
}

/// Type alias for URL encoded http requests.
pub type UrlEncRequest =
  Request(List(#(String, String)))

/// Creates a String representation of a token request
pub fn to_string_token_response(resp: AccessTokenResponse) {
  "AccessTokenResponse(
    access_token: " <> resp.access_token <> ",
    token_type: " <> resp.token_type <> ",
    expires_in: " <> option.unwrap(
    option.map(resp.expires_in, int.to_string),
    "None",
  ) <> "),
    refresh_token: " <> option.unwrap(resp.refresh_token, "None") <> ",
    scope: [" <> string.join(resp.scope, ", ") <> "],
  )"
}

pub fn to_string_token_request(req: TokenRequest) {
  case req {
    AuthorizationCodeGrantTokenRequest(
      token_endpoint,
      authentication,
      redirect_uri,
      code,
    ) ->
      "AuthorizationCodeGrantTokenRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> to_string_client_authentication(authentication)
      <> ", "
      <> "redirect_uri="
      <> option.map(redirect_uri, uri.to_string)
      |> option.unwrap("None")
      <> ", "
      <> "code="
      <> code
      <> ")"

    ResourceOwnerCredentialsGrantTokenRequest(
      token_endpoint,
      authentication,
      username,
      password,
      scope,
    ) ->
      "ResourceOwnerCredentialsGrantTokenRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> to_string_client_authentication(authentication)
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

    RefreshTokenGrantRequest(
      token_endpoint,
      authentication,
      refresh_token,
      scope,
    ) ->
      "RefreshTokenGrantRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> to_string_client_authentication(authentication)
      <> ", "
      <> "refresh_token="
      <> refresh_token
      <> ", "
      <> "scope="
      <> string.join(scope, " ")
      <> ")"

    ClientCredentialsGrantTokenRequest(token_endpoint, authentication, scope) ->
      "ClientCredentialsGrantTokenRequest("
      <> "token_endpoint="
      <> uri.to_string(token_endpoint)
      <> ", "
      <> "authentication="
      <> to_string_client_authentication(authentication)
      <> ", "
      <> "scope="
      <> string.join(scope, " ")
      <> ")"
  }
}

pub fn to_string_client_authentication(
  client_auth: ClientAuthentication,
) -> String {
  case client_auth {
    ClientSecretBasic(client_id:, ..) ->
      "ClientSecretBasic("
      <> "client_id="
      <> client_id.value
      <> ", "
      <> "client_secret=***"
      <> ")"

    ClientSecretPost(client_id:, ..) ->
      "ClientSecretPost("
      <> "client_id="
      <> client_id.value
      <> ", "
      <> "client_secret=***"
      <> ")"

    PublicAuthentication(client_id:) ->
      "PublicAuthentication(" <> "client_id=" <> client_id.value <> ")"
    ClientAssertion(client_id:, client_assertion_type:, ..) ->
      "ClientSecretJwt("
      <> "client_id="
      <> client_id.value
      <> ", "
      <> "client_assertion=***, "
      <> "client_assertion_type="
      <> client_assertion_type
      <> ")"
  }
}

pub type RequestModifier =
  fn(UrlEncRequest) -> Result(UrlEncRequest, RequestError)

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
      |> add_if_present(redirect_uri)
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

fn apply_modifiers(
  request: UrlEncRequest,
  modifiers: List(RequestModifier),
) -> Result(UrlEncRequest, RequestError) {
  list.fold(over: modifiers, from: Ok(request), with: result.try)
}

fn request_body_to_string(request: UrlEncRequest) -> request.Request(String) {
  request.body
  |> uri.query_to_string()
  |> request.set_body(request, _)
}

/// Function that adds a scope to a list if the scope is not empty.
fn add_scope(
  d: List(#(String, String)),
  scope: Scope,
) -> List(#(String, String)) {
  case scope {
    [_, ..] as scope -> option.Some(#("scope", scope |> string.join(" ")))
    _ -> option.None
  }
  |> add_if_present(d, _)
}

/// A helper function that maps a general request with credentials to a gleam http request.
/// The credentials are either attached to the request body URL encoded or added as basic `authorization` header.
fn setup_request(
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
    ClientSecretBasic(client_id, client_secret) -> fn(req: UrlEncRequest) {
      use <- bool.guard(
        when: client_secret |> is_secret_invalid,
        return: Error(SecretExpired),
      )
      req
      |> http_headers.set_basic(client_id.value, client_secret.value)
      |> Ok()
    }
    ClientSecretPost(client_id, client_secret) -> fn(req: UrlEncRequest) {
      use <- bool.guard(
        when: client_secret |> is_secret_invalid,
        return: Error(SecretExpired),
      )
      let body =
        req.body
        |> list.append(
          [
            #("client_id", client_id.value),
            #("client_secret", client_secret.value),
          ],
          _,
        )
      req
      |> request.set_body(body)
      |> Ok()
    }
    PublicAuthentication(client_id) -> fn(req: UrlEncRequest) {
      let body =
        req.body
        |> list.append(
          [
            #("client_id", client_id.value),
          ],
          _,
        )
      req
      |> request.set_body(body)
      |> Ok()
    }
    ClientAssertion(client_id, client_assertion, client_assertion_type) -> fn(
      req: UrlEncRequest,
    ) {
      let body =
        req.body
        |> list.append(
          [
            #("client_id", client_id.value),
            #("client_assertion_type", client_assertion_type),
            #("client_assertion", client_assertion),
          ],
          _,
        )
      req
      |> request.set_body(body)
      |> Ok()
    }
  }
}

/// Parses a token response and returns the access and refresh token if valid response, otherwise the error response.
pub fn parse_token_response(
  response: response.Response(String),
) -> Result(AccessTokenResponse, ResponseError) {
  case response.status {
    200 -> parse_token_success_response(response)
    _ -> parse_error_response(response) |> Error()
  }
}

fn parse_token_success_response(
  response: response.Response(String),
) -> Result(AccessTokenResponse, ResponseError) {
  let token_decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use expires_in <- decode.optional_field(
      "expires_in",
      option.None,
      decode.optional(decode.int),
    )
    use refresh_token <- decode.optional_field(
      "refresh_token",
      option.None,
      decode.optional(decode.string),
    )
    use scope <- decode.optional_field(
      "scope",
      option.None,
      decode.optional(decode.string),
    )
    let scope = scope |> option.map(parse_scope) |> option.unwrap([])
    decode.success(AccessTokenResponse(
      access_token: access_token,
      token_type: token_type,
      expires_in: expires_in,
      refresh_token: refresh_token,
      scope: scope,
    ))
  }
  json.parse(from: response.body, using: token_decoder)
  |> result.map_error(ParseError)
}

/// Parses an OAuth 2.0 error response defined in [RFC6749 Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
pub fn parse_error_response(
  response: response.Response(String),
) -> ResponseError {
  let error_decoder = {
    use error <- decode.field("error", decode.string)
    use error_description <- decode.optional_field(
      "error_description",
      option.None,
      decode.optional(decode.string),
    )
    use error_uri <- decode.optional_field(
      "error_uri",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(ErrorResponse(
      status: response.status,
      error: error,
      error_description: error_description,
      error_uri: error_uri,
    ))
  }
  json.parse(from: response.body, using: error_decoder)
  |> result.map_error(ParseError)
  |> helpers.unwrap_both()
}

/// Checks if a given secret is not expired.
/// Returns always true for secrets that cannot expire.
pub fn secret_is_valid(secret: Secret) -> Bool {
  case secret {
    Secret(_) -> True
    SecretWithExpiration(_, expires_at) ->
      timestamp.compare(expires_at, timestamp.system_time()) == order.Lt
  }
  |> bool.negate()
}

/// Checks if a given secret is expired.
/// Returns always false for secrets that cannot expire.
pub fn is_secret_invalid(secret: Secret) -> Bool {
  case secret {
    Secret(_) -> False
    SecretWithExpiration(_, _) -> secret |> secret_is_valid |> bool.negate
  }
}

/// Parses a string containing the space separated scopes.
///
/// ## Example
/// ```gleam
/// parse_scope("scope1 scope2")
/// ````
pub fn parse_scope(scope: String) -> Scope {
  scope
  |> string.trim()
  |> string.split(" ")
  |> list.filter(string_not_empty)
}

fn string_not_empty(l: String) -> Bool {
  !string.is_empty(l)
}
