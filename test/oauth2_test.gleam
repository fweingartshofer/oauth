import gleam/io
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import gleeunit
import gleeunit/should
import oauth2

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn parse_scope_with_two_scopes_test() {
  // Given
  let scope = "scope1 scope2"

  // When
  let res = oauth2.parse_scope(scope)

  // Then
  res |> should.equal(["scope1", "scope2"])
}

pub fn parse_scope_with_extra_spaces_test() {
  // Given
  let scope = " scope1  scope2 "

  // When
  let res = oauth2.parse_scope(scope)

  // Then
  res |> should.equal(["scope1", "scope2"])
}

pub fn parse_scope_with_empty_string_test() {
  // Given
  let scope = "  "

  // When
  let res = oauth2.parse_scope(scope)

  // Then
  res |> should.equal([])
}

pub fn random_state32_test() {
  // Given
  // When
  let res = oauth2.random_state32()

  // Then
  res |> string.length() |> should.equal(32)
}

pub fn random_state_test() {
  // Given
  // When
  let res = oauth2.random_state(10)

  // Then
  res |> string.length() |> should.equal(10)
}

pub fn make_redirect_uri_test() {
  // Given
  let assert Ok(u) = uri.parse("https://example.com/oauth2/?q=asdf")
  let response_type = oauth2.Code
  let redirect_uri = "http://localhost:8080/callback"
  let client_id = oauth2.ClientId("client-id")
  let scope = ["scope1", "scope2"]
  let state = "state"
  let expected =
    uri.Uri(
      scheme: option.Some("https"),
      userinfo: option.None,
      host: option.Some("example.com"),
      port: option.None,
      path: "/oauth2/",
      query: option.Some(
        "response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&client_id=client-id&scope=scope1%20scope2&state=state",
      ),
      fragment: option.None,
    )

  // When
  let res =
    oauth2.make_redirect_uri(
      u,
      response_type,
      redirect_uri,
      client_id,
      scope,
      state,
    )

  // Then
  res |> should.equal(expected)
}
