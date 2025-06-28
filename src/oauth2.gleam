import gleam/list
import gleam/option
import gleam/string
import gleam/time/timestamp
import gleam/uri
import gleam/yielder
import helpers
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

pub type State =
  String

pub fn make_redirect_uri(
  server: uri.Uri,
  response_type: ResponseType,
  redirect_uri: String,
  client_id: ClientId,
  scope: Scope,
  state: State,
) -> uri.Uri {
  let queries = [
    #("response_type", response_type_to_string(response_type)),
    #("redirect_uri", redirect_uri),
    #("client_id", client_id.value),
    #("scope", string.join(scope, " ")),
    #("state", state),
  ]
  uri.Uri(..server, query: option.Some(uri.query_to_string(queries)))
}

pub fn parse_scope(scope: String) -> Scope {
  scope
  |> string.trim()
  |> string.split(" ")
  |> list.filter(helpers.string_not_empty)
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
