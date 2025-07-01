import gleam/bit_array
import gleam/bool
import gleam/hackney
import gleam/http
import gleam/http/request
import gleam/io
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

pub fn to_http_request(
  request: TokenRequest,
) -> Result(request.Request(String), Error) {
  case request {
    AuthorizationCodeGrantTokenRequest(server, client_auth, redirect_uri, code) -> {
      let redirect_uri = to_redirect_uri_query(redirect_uri)
      let body =
        uri.query_to_string(
          [
            #("grant_type", "authorization_code"),
            #("client_id", client_auth.client_id.value),
            #("code", code),
          ]
          |> add_if_present(redirect_uri),
        )
      {
        let server = uri.Uri(..server, query: option.None)
        use request <- result.map(request.from_uri(server))
        request
        |> request.set_method(http.Post)
        |> request.set_header(
          "content-type",
          "application/x-www-form-urlencoded",
        )
        |> request.set_body(body)
        |> add_authentication_to_request(client_auth)
      }
      |> result.map_error(fn(_x) { InvalidUri })
      |> result.flatten()
    }
  }
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
    ClientSecretPost(_client_id, client_secret) -> {
      client_secret
      |> secret_is_valid()
      |> bool.guard(Error(SecretExpired), fn() {
        req
        |> request.set_body(
          uri.query_to_string([
            #("client_secret", client_secret.value),
            ..uri.parse_query(req.body)
            |> result.unwrap([])
          ]),
        )
        |> Ok()
      })
    }
    PublicAuthentication(_client_id) -> Ok(req)
  }
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
