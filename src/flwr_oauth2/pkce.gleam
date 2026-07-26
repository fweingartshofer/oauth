//// This module provides functions to create PKCE Verifiers and Challens as per [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636).

import flwr_oauth2/authentication
import flwr_oauth2/helpers
import flwr_oauth2/token_request
import gleam/bit_array
import gleam/crypto
import gleam/http/request
import gleam/list
import gleam/option
import gleam/uri

/// The code verifier
pub type Verifier {
  Verifier(value: String)
}

/// The code challenge created from a code verifier
pub type Challenge {
  Challenge(value: String)
}

pub type AuthorizationCodeGrantTokenRequestWithPKCE {
  /// A token request for the Authorization Code Grant Type with a PKCE code verifier.
  /// Use the [`AuthorizationCodeGrantRedirectUri`](#AuthorizationCodeGrantRedirectUri) to retrieve the `code`.
  /// See [RFC6749 Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) and [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636).
  AuthorizationCodeGrantTokenRequestWithPKCE(
    token_endpoint: uri.Uri,
    authentication: authentication.ClientAuthentication,
    redirect_uri: option.Option(uri.Uri),
    code: String,
    code_verifier: String,
  )
}

const valid_verifier_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  <> "abcdefghijklmnopqrstuvwxyz"
  <> "0123456789"
  <> "-._~"

pub fn to_http_request(request: AuthorizationCodeGrantTokenRequestWithPKCE) {
  let AuthorizationCodeGrantTokenRequestWithPKCE(
    token_endpoint:,
    authentication:,
    redirect_uri:,
    code:,
    code_verifier:,
  ) = request
  token_request.AuthorizationCodeGrantTokenRequest(
    token_endpoint:,
    authentication:,
    redirect_uri:,
    code:,
  )
  |> token_request.to_http_request_with_modifiers([
    code_verifier_modifier(code_verifier),
  ])
}

fn code_verifier_modifier(code_verifier: String) {
  fn(req: request.Request(List(#(String, String)))) {
    req.body
    |> list.append([
      #("code_verifier", code_verifier),
    ])
    |> request.set_body(req, _)
    |> Ok
  }
}

pub fn to_string(request: AuthorizationCodeGrantTokenRequestWithPKCE) {
  let AuthorizationCodeGrantTokenRequestWithPKCE(
    token_endpoint:,
    authentication: auth,
    redirect_uri:,
    code:,
    code_verifier:,
  ) = request
  "AuthorizationCodeGrantTokenRequestWithPKCE("
  <> "token_endpoint="
  <> uri.to_string(token_endpoint)
  <> ", "
  <> "authentication="
  <> authentication.to_string(auth)
  <> ", "
  <> "redirect_uri="
  <> option.map(redirect_uri, uri.to_string)
  |> option.unwrap("None")
  <> ", "
  <> "code="
  <> code
  <> ", "
  <> "code_verifier="
  <> code_verifier
  <> ")"
}

/// Creates a new code verifier as per [RFC7636 4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1).
/// Uses a default length for the verifier of 128.
/// 
/// For the definition of the code verifier see this excerpt from RFC7636:
/// > high-entropy cryptographic random STRING using the
/// > unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
/// > from Section 2.3 of [RFC3986], with a minimum length of 43 characters
/// > and a maximum length of 128 characters.
pub fn new() -> Verifier {
  helpers.generate_random_string(chars: valid_verifier_chars, length: 128)
  |> Verifier()
}

/// Creates a code challenge from a given verifier.
/// The given code verifier should conform to the RFC7636 definition of a code verifier, otherwise the resulting code challenge will be invalid.
pub fn to_challenge(verifier: Verifier) -> Challenge {
  verifier.value
  |> bit_array.from_string()
  |> crypto.hash(crypto.Sha256, _)
  |> bit_array.base64_url_encode(False)
  |> Challenge
}
