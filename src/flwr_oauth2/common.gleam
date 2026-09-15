import gleam/bool
import gleam/dynamic/decode.{type Decoder}
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/order
import gleam/string
import gleam/time/timestamp
import gleam/uri.{type Uri}

/// Type alias for the scope.
/// A scope is a list of strings.
/// See [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
pub type Scope =
  List(String)

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

/// Type to indicate the client ID.
/// Mostly used to have type-safe parameters, so client id, client secret, etc are not mixed up.
/// See [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
pub type ClientId {
  ClientId(value: String)
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

pub fn uri_decoder(raw_uri: String) -> Decoder(Uri) {
  case uri.parse(raw_uri) {
    Ok(res) -> decode.success(res)
    _ -> decode.failure(uri.empty, "Invalid URI")
  }
}

pub fn uri_to_json(raw_uri: Uri) -> Json {
  json.string(uri.to_string(raw_uri))
}

pub fn json_attach_member(
  entries: List(#(String, Json)),
  name: String,
  value: Option(a),
  to_json: fn(a) -> Json,
) -> List(#(String, Json)) {
  case value |> option.map(to_json) {
    option.Some(value) -> list.append(entries, [#(name, value)])
    option.None -> entries
  }
}

pub fn json_attach_list_member(
  entries: List(#(String, Json)),
  name: String,
  values: List(a),
  to_json: fn(a) -> Json,
) -> List(#(String, Json)) {
  case values {
    [] -> entries
    _ -> list.append(entries, [#(name, json.array(values, to_json))])
  }
}
