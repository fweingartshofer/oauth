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
import gleam/yielder
import prng/random

pub type ResponseType {
  Code
  Token
}

pub type ClientId {
  ClientId(value: String)
}

pub type Secret {
  Secret(value: String)
  SecretWithExpiration(value: String, expires_at: timestamp.Timestamp)
}

pub type Scope =
  List(String)

pub type State {
  State(value: String)
}

pub type TokenRequest {
  AuthorizationCodeGrantTokenRequest(
    server: uri.Uri,
    authentication: ClientAuthentication,
    redirect_uri: option.Option(uri.Uri),
    code: String,
  )
  ResourceOwnerCredentialsGrantTokenRequest(
    server: uri.Uri,
    authentication: ClientAuthentication,
    username: String,
    password: String,
    scope: Scope,
  )
  RefreshTokenGrantRequest(
    server: uri.Uri,
    authentication: ClientAuthentication,
    refresh_token: String,
    scope: Scope,
  )
}

pub type ClientAuthentication {
  ClientSecretBasic(client_id: ClientId, client_secret: Secret)
  ClientSecretPost(client_id: ClientId, client_secret: Secret)
  PublicAuthentication(client_id: ClientId)
}

pub type Error {
  SecretExpired
  InvalidUri
}

pub type AccessTokenResponse {
  TokenErrorResponse(
    status: Int,
    error: String,
    error_description: option.Option(String),
    error_uri: option.Option(String),
  )
  AccessTokenResponse(
    access_token: String,
    token_type: String,
    expires_in: option.Option(Int),
    refresh_token: option.Option(String),
    scope: Scope,
  )
}

type OauthRequest {
  OauthRequest(
    token_endpoint: uri.Uri,
    body: List(#(String, String)),
    headers: List(#(String, String)),
  )
}

/// Creates the uri that the resource owner should be redirected too.
pub fn make_redirect_uri(
  oauth_server server: uri.Uri,
  response_type response_type: ResponseType,
  redirect_uri redirect_uri: option.Option(uri.Uri),
  client_id client_id: ClientId,
  scope scope: Scope,
  state state: option.Option(State),
) -> uri.Uri {
  let state =
    state |> option.map(fn(x) { x.value }) |> option.map(wrap_tuple("state", _))
  let redirect_uri = to_redirect_uri_query(redirect_uri)
  let queries =
    [
      #("response_type", response_type_to_string(response_type)),
      #("client_id", client_id.value),
      #("scope", string.join(scope, " ")),
    ]
    |> add_if_present(redirect_uri)
    |> add_if_present(state)
  uri.Uri(..server, query: option.Some(uri.query_to_string(queries)))
}

/// Creates a http request from the given TokenRequest, but does not send.
/// Sending the request is done by the user of the function.
pub fn to_http_request(
  request: TokenRequest,
) -> Result(request.Request(String), Error) {
  case request {
    AuthorizationCodeGrantTokenRequest(_server, client_auth, redirect_uri, code) -> {
      let redirect_uri = to_redirect_uri_query(redirect_uri)
      [#("grant_type", "authorization_code"), #("code", code)]
      |> add_if_present(redirect_uri)
    }
    ResourceOwnerCredentialsGrantTokenRequest(
      server: _server,
      authentication: _client_auth,
      username: username,
      password: password,
      scope: scope,
    ) -> {
      let scope = case list.is_empty(scope) {
        False -> option.Some(#("scope", scope |> string.join(" ")))
        True -> option.None
      }
      [
        #("grant_type", "password"),
        #("username", username),
        #("password", password),
      ]
      |> add_if_present(scope)
    }
    RefreshTokenGrantRequest(_server, _client_auth, refresh_token, scope) -> {
      let scope = case list.is_empty(scope) {
        False -> option.Some(#("scope", scope |> string.join(" ")))
        True -> option.None
      }
      [#("grant_type", "refresh_token"), #("refresh_token", refresh_token)]
      |> add_if_present(scope)
    }
  }
  |> uri.query_to_string()
  |> setup_request(
    server: request.server,
    body: _,
    client_auth: request.authentication,
  )
}

fn setup_request(
  server server: uri.Uri,
  body body: String,
  client_auth client_auth: ClientAuthentication,
) {
  let server = uri.Uri(..server, query: option.None)
  {
    use request <- result.map(request.from_uri(server))
    request
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_body(body)
    |> add_authentication_to_request(client_auth)
  }
  |> result.map_error(fn(_x) { InvalidUri })
  |> result.flatten()
}

fn add_authentication_to_request(
  req: request.Request(String),
  auth: ClientAuthentication,
) -> Result(request.Request(String), Error) {
  case auth {
    ClientSecretBasic(client_id, client_secret) -> {
      client_secret
      |> secret_is_valid()
      |> bool.guard(Error(SecretExpired), fn() {
        let encoded =
          { client_id.value <> ":" <> client_secret.value }
          |> bit_array.from_string()
          |> bit_array.base64_encode(False)
        request.set_header(req, "authentication", "Basic " <> encoded)
        |> Ok()
      })
    }
    ClientSecretPost(client_id, client_secret) -> {
      client_secret
      |> secret_is_valid()
      |> bool.guard(Error(SecretExpired), fn() {
        req
        |> request.set_body(
          uri.query_to_string([
            #("client_id", client_id.value),
            #("client_secret", client_secret.value),
            ..uri.parse_query(req.body)
            |> result.unwrap([])
          ]),
        )
        |> Ok()
      })
    }
    PublicAuthentication(client_id) ->
      req
      |> request.set_body(
        uri.query_to_string([
          #("client_id", client_id.value),
          ..uri.parse_query(req.body)
          |> result.unwrap([])
        ]),
      )
      |> Ok()
  }
}

/// Parses a token response and returns the access and refresh token if valid response, otherwise the error response.
pub fn parse_token_response(
  response: response.Response(String),
) -> Result(AccessTokenResponse, json.DecodeError) {
  case response.status {
    200 -> parse_token_success_response(response)
    _ -> parse_token_error_response(response)
  }
}

fn parse_token_success_response(
  response: response.Response(String),
) -> Result(AccessTokenResponse, json.DecodeError) {
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
}

fn parse_token_error_response(
  response: response.Response(String),
) -> Result(AccessTokenResponse, json.DecodeError) {
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
    decode.success(TokenErrorResponse(
      status: response.status,
      error: error,
      error_description: error_description,
      error_uri: error_uri,
    ))
  }
  json.parse(from: response.body, using: error_decoder)
}

/// Checks if a given secret is not expired.
/// Returns always true for secrets that cannot expire.
pub fn secret_is_valid(secret: Secret) -> Bool {
  case secret {
    Secret(_) -> False
    SecretWithExpiration(_, expires_at) ->
      timestamp.compare(expires_at, timestamp.system_time()) == order.Lt
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

const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/// Generates a random State with the specified length including only uppercase and lowercase letters
/// If length <= 0 returns an empty string
pub fn random_state(length: Int) -> State {
  let assert yielder.Next(value, _) =
    random.fixed_size_list(random.int(0, 51), length)
    |> random.to_random_yielder()
    |> yielder.step()

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

fn add_if_present(d: List(a), value: option.Option(a)) -> List(a) {
  value
  |> option.map(list.wrap)
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
