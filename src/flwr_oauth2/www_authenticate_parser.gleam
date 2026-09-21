//// This module parses [RFC7235 WWW-Authenticate headers](https://datatracker.ietf.org/doc/html/rfc7235#section-4.1),
//// as produced by authorization servers on 401 responses (e.g. the `Bearer`
//// challenge defined by [RFC6750 §3](https://datatracker.ietf.org/doc/html/rfc6750#section-3)).
////
//// It supports the common challenge formats — schemes with `key=value`
//// parameters, quoted strings, and multiple comma-separated challenges —
//// but not token68 credentials.
////
//// Use [parse](#parse) to turn a header value into a list of [Challenge](#Challenge) values,
//// or [lex](#lex) to work with the raw token stream.

import gleam/list
import gleam/string

/// A parsed challenge from a WWW-Authenticate header:
/// the auth scheme (e.g. `Bearer`) and its parameters
/// (e.g. `[#("realm", "example"), #("error", "invalid_token")]`).
pub type Challenge {
  Challenge(scheme: String, parameters: List(#(String, String)))
}

/// Errors returned when a WWW-Authenticate header cannot be parsed.
pub type ParserError {
  UnexpectedToken(token: Token)
}

/// Implements a parser to parse [RFC7235 WWW-Authenticate Headers](https://datatracker.ietf.org/doc/html/rfc7235#section-4.1)
/// The parser can parse the most common WWW-Authenticate formats, but not token68.
pub fn parse(www_authenticate source: String) {
  lex(source) |> list.filter(fn(x) { x != Whitespace }) |> do_parse([])
}

fn do_parse(
  tokens: List(Token),
  tree: List(Challenge),
) -> Result(List(Challenge), ParserError) {
  case tokens {
    [] -> tree |> list.reverse() |> Ok
    [Comma, ..tail] -> do_parse(tail, tree)
    [Text(scheme), ..tail] -> {
      let #(rest, parameters) = parse_parameters(tail, [])
      do_parse(rest, [Challenge(scheme:, parameters:), ..tree])
    }
    [token, ..] -> Error(UnexpectedToken(token))
  }
}

fn parse_parameters(
  tokens: List(Token),
  parameters: List(#(String, String)),
) -> #(List(Token), List(#(String, String))) {
  case tokens {
    [Comma, ..tail] -> parse_parameters(tail, parameters)
    [Text(key), Equals, Quote, Text(value), Quote, ..tail]
    | [Text(key), Equals, Text(value), ..tail] ->
      parse_parameters(tail, [#(key, unescape(value, "")), ..parameters])
    [Text(key), Equals, Quote, Quote, ..tail] ->
      parse_parameters(tail, [#(key, ""), ..parameters])
    _ -> #(tokens, parameters |> list.reverse())
  }
}

fn unescape(source: String, acc: String) -> String {
  case source {
    "\\\\" <> tail -> unescape(tail, acc <> "\\")
    "\\\"" <> tail -> unescape(tail, acc <> "\"")
    _ ->
      case string.pop_grapheme(source) {
        Ok(#(head, tail)) -> unescape(tail, acc <> head)
        Error(Nil) -> acc
      }
  }
}

/// A token produced by [lex](#lex).
/// `Text` holds raw characters; a backslash-escaped quote inside a
/// quoted-string stays raw in `Text` and is unescaped during parsing.
pub type Token {
  Text(value: String)
  Comma
  Quote
  Equals
  Whitespace
}

/// A lexer that can lex [RFC7235 WWW-Authenticate Headers](https://datatracker.ietf.org/doc/html/rfc7235#section-4.1)
/// If parsing of the WWW-Authenticate Header is required see [parse](#parse).
pub fn lex(source: String) {
  do_lex(source, [], [], OutQuote)
}

type State {
  InQuote
  OutQuote
}

fn do_lex(
  source: String,
  buf: List(String),
  tokens: List(Token),
  state: State,
) -> List(Token) {
  case source {
    "\"" <> tail if state == InQuote ->
      do_lex(tail, [], [Quote, ..add_text(buf, tokens)], OutQuote)
    "\"" <> tail -> do_lex(tail, [], [Quote, ..add_text(buf, tokens)], InQuote)
    "=" <> tail if state == OutQuote ->
      do_lex(tail, [], [Equals, ..add_text(buf, tokens)], state)
    " " <> tail
      | "\t" <> tail
      | "\n" <> tail
      | "\r" <> tail
      if state == OutQuote
    ->
      tail
      |> string.trim_start
      |> do_lex([], [Whitespace, ..add_text(buf, tokens)], state)
    "," <> tail if state == OutQuote ->
      do_lex(tail, [], [Comma, ..add_text(buf, tokens)], state)
    "\\\"" <> tail -> do_lex(tail, ["\\\"", ..buf], tokens, state)
    _ ->
      case string.pop_grapheme(source) {
        Error(Nil) -> finish(buf, tokens)
        Ok(#(head, tail)) -> do_lex(tail, [head, ..buf], tokens, state)
      }
  }
}

fn add_text(buf: List(String), tokens: List(Token)) -> List(Token) {
  case buf {
    [] -> tokens
    _ -> [Text(buf |> list.reverse() |> string.concat), ..tokens]
  }
}

fn finish(buf: List(String), tokens: List(Token)) -> List(Token) {
  tokens
  |> add_text(buf, _)
  |> list.reverse()
}
