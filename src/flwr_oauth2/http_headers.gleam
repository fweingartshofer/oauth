//// Helper module to collect useful setters for HTTP headers, such as the authorization header.

import gleam/bit_array
import gleam/http/request

/// Name for the HTTP Authorization Header
pub const authorization_header = "authorization"

pub fn set_bearer(
  req: request.Request(a),
  bearer_token: String,
) -> request.Request(a) {
  req
  |> request.set_header(authorization_header, "Bearer " <> bearer_token)
}

pub fn set_basic(
  req: request.Request(a),
  client_id: String,
  client_secret: String,
) {
  req
  |> request.set_header(
    "Authorization",
    "Basic " <> encode_base64(client_id, client_secret),
  )
}

pub fn encode_base64(client_id: String, client_secret: String) {
  { client_id <> ":" <> client_secret }
  |> bit_array.from_string()
  |> bit_array.base64_encode(True)
}
