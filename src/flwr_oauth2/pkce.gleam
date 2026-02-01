//// This module provides functions to create PKCE Verifiers and Challens as per [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636).

import flwr_oauth2/helpers
import gleam/bit_array
import gleam/crypto

/// The code verifier
pub type Verifier {
  Verifier(value: String)
}

/// The code challenge created from a code verifier
pub type Challenge {
  Challenge(value: String)
}

const valid_verifier_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  <> "abcdefghijklmnopqrstuvwxyz"
  <> "0123456789"
  <> "-._~"

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
