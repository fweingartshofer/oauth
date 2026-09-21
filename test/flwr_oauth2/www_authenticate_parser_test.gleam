import flwr_oauth2/www_authenticate_parser.{
  Challenge, Comma, Equals, Quote, Text, UnexpectedToken, Whitespace,
}
import gleeunit/should

pub fn lexer_test() {
  // Given
  let auth =
    "Newauth realm=\"apps\", type=1, empty=,
     title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\""

  // When
  let res = www_authenticate_parser.lex(auth)

  // Then
  res
  |> should.equal([
    Text("Newauth"),
    Whitespace,
    Text("realm"),
    Equals,
    Quote,
    Text("apps"),
    Quote,
    Comma,
    Whitespace,
    Text("type"),
    Equals,
    Text("1"),
    Comma,
    Whitespace,
    Text("empty"),
    Equals,
    Comma,
    Whitespace,
    Text("title"),
    Equals,
    Quote,
    Text("Login to \\\"apps\\\""),
    Quote,
    Comma,
    Whitespace,
    Text("Basic"),
    Whitespace,
    Text("realm"),
    Equals,
    Quote,
    Text("simple"),
    Quote,
  ])
}

pub fn parser_test() {
  // Given
  let auth =
    "Newauth realm=\"apps\", type=1,
     title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\", error = \"invalid_token\", error_description=\"\", error_uri =\"\""

  // When
  let res = www_authenticate_parser.parse(auth)

  // Then
  res
  |> should.be_ok()
  |> should.equal([
    Challenge("Newauth", [
      #("realm", "apps"),
      #("type", "1"),
      #("title", "Login to \"apps\""),
    ]),
    Challenge("Basic", [
      #("realm", "simple"),
      #("error", "invalid_token"),
      #("error_description", ""),
      #("error_uri", ""),
    ]),
  ])
}

pub fn parser_token68_test() {
  // Given
  let auth = "Token68="

  // When
  let res = www_authenticate_parser.parse(auth)

  // Then
  res
  |> should.be_error()
  |> should.equal(UnexpectedToken(Equals))
}

pub fn parser_error_test() {
  // Given
  let auth = "Newauth realm=\"apps\", type=1\""

  // When
  let res = www_authenticate_parser.parse(auth)

  // Then
  res
  |> should.be_error()
  |> should.equal(UnexpectedToken(Quote))
}
