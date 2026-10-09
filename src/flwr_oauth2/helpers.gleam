//// Helper functions

import gleam/bool
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

/// Appends the value if present a given list
pub fn add_if_present(d: List(a), value: option.Option(a)) -> List(a) {
  [value]
  |> option.values
  |> list.append(d)
}

pub fn unwrap_both(res: Result(a, a)) -> a {
  case res {
    Ok(res) -> res
    Error(res) -> res
  }
}

pub fn encode_redirect_uri(
  value: option.Option(uri.Uri),
) -> option.Option(#(String, String)) {
  value
  |> option.map(uri.to_string)
  |> option.map(fn(x) { #("redirect_uri", x) })
}

/// Generates a random string from a given list of characters with a given length
pub fn generate_random_string(
  chars chars: String,
  length length: Int,
) -> String {
  generate_random_string_rec("", 0, length, chars)
}

fn generate_random_string_rec(
  generated: String,
  index: Int,
  length: Int,
  chars: String,
) -> String {
  case index == length {
    True -> generated
    False -> {
      chars
      |> string.length()
      |> int.random()
      |> string.slice(from: chars, at_index: _, length: 1)
      |> concat_strings(generated, _)
      |> generate_random_string_rec(index + 1, length, chars)
    }
  }
}

fn concat_strings(left: String, right: String) -> String {
  left <> right
}

/// Convenience method that matches if a request contains the correct content type.
/// Returns Ok(Nil) if type matches, otherwise returns an Error with the given content type.
pub fn verify_content_type(
  response resp: response.Response(a),
  expected expected_content_type: String,
) -> Result(Nil, String) {
  let ct = response.get_header(resp, "content-type")
  ct
  |> result.map(fn(source) {
    let x = drop_after(source:, after: ";") |> string.lowercase()
    bool.guard(expected_content_type == x, Ok(Nil), fn() { Error(source) })
  })
  |> result.unwrap(Ok(Nil))
}

fn drop_after(source source: String, after after: String) -> String {
  case string.split_once(source, after) {
    Ok(#(head, _)) -> head
    _ -> source
  }
}
