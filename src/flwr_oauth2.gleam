import flwr_oauth2/helpers.{add_if_present}
import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/list
import gleam/option
import gleam/order
import gleam/result
import gleam/string
import gleam/time/timestamp
import gleam/uri
import prng/random

/// Type to indicate the response type of the authorization code and implicit grant.
/// Must always be "code" for the authorizatin code grant and alway be "token" for the implicit grant.
/// For more information see [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1).
pub type ResponseType {
  Code
  Token
}

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

/// Type to indicate the state.
/// Mostly used to have type-safe parameters, so other string parameters are not mixed up.
/// See [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
pub type State {
  State(value: String)
}

/// This defines a redirect url defined by [RFC6749 Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).
pub type AuthorizationCodeGrantRedirectUri {
  /// Represents a standard redirect url without any extensions.
  AuthorizationCodeGrantRedirectUri(
    oauth_server: uri.Uri,
    response_type: ResponseType,
    redirect_uri: option.Option(uri.Uri),
    client_id: ClientId,
    scope: Scope,
    state: option.Option(State),
  )
  /// Represents a redirect url with a PKCE code challenge.
  /// See [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636).
  AuthorizationCodeGrantRedirectUriWithPKCE(
    oauth_server: uri.Uri,
    response_type: ResponseType,
    redirect_uri: option.Option(uri.Uri),
    client_id: ClientId,
    scope: Scope,
    state: option.Option(State),
    code_challenge: String,
    code_challenge_method: CodeChallengeMethod,
  )
}

/// The kind of code challenge method used for the PKCE extension.
/// See [RFC7636 Client Creates Code Challenge](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2)
pub type CodeChallengeMethod {
  Plain
  S256
}

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
  /// A token request for the Authorization Code Grant Type with a PKCE code verifier.
  /// Use the [`AuthorizationCodeGrantRedirectUri`](#AuthorizationCodeGrantRedirectUri) to retrieve the `code`.
  /// See [RFC6749 Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) and [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636).
  AuthorizationCodeGrantTokenRequestWithPKCE(
    token_endpoint: uri.Uri,
    authentication: ClientAuthentication,
    redirect_uri: option.Option(uri.Uri),
    code: String,
    code_verifier: String,
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
  /// Use this type if the client is public and there is not client secret to be included.
  PublicAuthentication(client_id: ClientId)
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

/// This type defines the credentials and where in the request they should be inserted.
type AuthLocation {
  /// Insert the OAuth 2.0 client credentials into the Header as `Authorization: Basic base64(clientId:clientSecret)` or `Authorization: Basic clientId:clientSecret`.
  Header(key: String, value: String)
  /// Insert the OAuth 2.0 client credentials into the request body as `client_id=<clientId>&client_secret=<clientSecret>`.
  /// Will not include the client secret for public clients.
  Body(value: List(#(String, String)))
}

/// Creates the uri that the resource owner should be redirected too.
pub fn make_redirect_uri(
  redirect_config: AuthorizationCodeGrantRedirectUri,
) -> uri.Uri {
  let state =
    redirect_config.state
    |> option.map(fn(x) { x.value })
    |> option.map(wrap_tuple("state", _))
  let redirect_uri = to_redirect_uri_query(redirect_config.redirect_uri)
  let code_callenge = case redirect_config {
    AuthorizationCodeGrantRedirectUriWithPKCE(
      _,
      _,
      _,
      _,
      _,
      _,
      code_challenge,
      method,
    ) ->
      option.Some([
        #("code_challenge", code_challenge),
        #("code_challenge_method", case method {
          Plain -> "plain"
          S256 -> "S256"
        }),
      ])
    _ -> option.None
  }
  let queries =
    [
      #("response_type", response_type_to_string(redirect_config.response_type)),
      #("client_id", redirect_config.client_id.value),
      #("scope", string.join(redirect_config.scope, " ")),
    ]
    |> add_if_present(redirect_uri)
    |> add_if_present(state)
    |> add_many_if_present(code_callenge)
  uri.Uri(
    ..redirect_config.oauth_server,
    query: option.Some(uri.query_to_string(queries)),
  )
}

/// Creates a http request from the given TokenRequest, but does not send.
/// Sending the request is done by the user of the function.
pub fn to_http_request(
  request: TokenRequest,
) -> Result(request.Request(String), RequestError) {
  case request {
    AuthorizationCodeGrantTokenRequest(
      _server,
      _client_auth,
      redirect_uri,
      code,
    ) -> {
      let redirect_uri = to_redirect_uri_query(redirect_uri)
      [#("grant_type", "authorization_code"), #("code", code)]
      |> add_if_present(redirect_uri)
    }
    AuthorizationCodeGrantTokenRequestWithPKCE(
      _server,
      _client_auth,
      redirect_uri,
      code,
      code_verifier,
    ) -> {
      let redirect_uri = to_redirect_uri_query(redirect_uri)
      [
        #("grant_type", "authorization_code"),
        #("code", code),
        #("code_verifier", code_verifier),
      ]
      |> add_if_present(redirect_uri)
    }
    ResourceOwnerCredentialsGrantTokenRequest(
      token_endpoint: _server,
      authentication: _client_auth,
      username: username,
      password: password,
      scope: scope,
    ) -> {
      [
        #("grant_type", "password"),
        #("username", username),
        #("password", password),
      ]
      |> add_scope(scope)
    }
    RefreshTokenGrantRequest(_server, _client_auth, refresh_token, scope) -> {
      [#("grant_type", "refresh_token"), #("refresh_token", refresh_token)]
      |> add_scope(scope)
    }
    ClientCredentialsGrantTokenRequest(_server, _client_auth, scope) -> {
      [
        #("grant_type", "client_credentials"),
      ]
      |> add_scope(scope)
    }
  }
  |> setup_request(
    endpoint: request.token_endpoint,
    body: _,
    client_auth: request.authentication,
  )
}

fn add_scope(
  d: List(#(String, String)),
  scope: Scope,
) -> List(#(String, String)) {
  case list.is_empty(scope) {
    False -> option.Some(#("scope", scope |> string.join(" ")))
    True -> option.None
  }
  |> add_if_present(d, _)
}

/// A helper function that maps a general request with credentials to a gleam http request.
/// The credentials are either attached to the request body URL encoded or added as basic `authorization` header.
pub fn setup_request(
  endpoint endpoint: uri.Uri,
  body body: List(#(String, String)),
  client_auth client_auth: ClientAuthentication,
) -> Result(request.Request(String), RequestError) {
  let req =
    request.from_uri(endpoint)
    |> result.map_error(fn(_x) { InvalidUri })
  {
    use req <- result.map(req)
    let req =
      req
      |> request.set_method(http.Post)
      |> request.set_header("content-type", "application/x-www-form-urlencoded")
    use auth_location <- result.map(create_authentication(client_auth))
    case auth_location {
      Header(key, value) ->
        req
        |> request.set_header(key, value)
        |> request.set_body(uri.query_to_string(body))
      Body(values) ->
        list.append(values, body)
        |> uri.query_to_string()
        |> request.set_body(req, _)
    }
  }
  |> result.flatten()
}

/// Encodes the ClientAuthentication that is to be sent to the OAuth 2.0 Server.
/// For Basic Authentication it will always encode it with base64.
fn create_authentication(
  auth: ClientAuthentication,
) -> Result(AuthLocation, RequestError) {
  case auth {
    ClientSecretBasic(client_id, client_secret) -> {
      client_secret
      |> secret_is_valid()
      |> bool.negate()
      |> bool.guard(Error(SecretExpired), fn() {
        let encoded =
          { client_id.value <> ":" <> client_secret.value }
          |> bit_array.from_string()
          |> bit_array.base64_encode(True)
        Header("authorization", "Basic " <> encoded)
        |> Ok()
      })
    }
    ClientSecretPost(client_id, client_secret) -> {
      client_secret
      |> secret_is_valid()
      |> bool.negate()
      |> bool.guard(Error(SecretExpired), fn() {
        Body([
          #("client_id", client_id.value),
          #("client_secret", client_secret.value),
        ])
        |> Ok()
      })
    }
    PublicAuthentication(client_id) ->
      Body([#("client_id", client_id.value)])
      |> Ok()
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
    Secret(_) -> False
    SecretWithExpiration(_, expires_at) ->
      timestamp.compare(expires_at, timestamp.system_time()) == order.Lt
  }
  |> bool.negate()
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

const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/// Generates a random State with the specified length including only uppercase and lowercase letters
/// If length <= 0 returns an empty string
pub fn random_state(length: Int) -> State {
  let #(value, _) =
    random.fixed_size_list(random.int(0, 51), length)
    |> random.step(random.new_seed(11))

  list.map(value, string.slice(from: chars, at_index: _, length: 1))
  |> string.join("")
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

fn string_not_empty(l: String) -> Bool {
  !string.is_empty(l)
}

fn add_many_if_present(d: List(a), value: option.Option(List(a))) -> List(a) {
  value
  |> option.unwrap([])
  |> list.append(d)
}

fn to_redirect_uri_query(
  value: option.Option(uri.Uri),
) -> option.Option(#(String, String)) {
  value
  |> option.map(uri.to_string)
  |> option.map(wrap_tuple("redirect_uri", _))
}

fn wrap_tuple(name: a, value: b) {
  #(name, value)
}
