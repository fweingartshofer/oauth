import gleam/http
import gleam/http/request
import gleam/io
import gleam/option
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
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
  res.value |> string.length() |> should.equal(32)
}

pub fn random_state_test() {
  // Given
  // When
  let res = oauth2.random_state(10)

  // Then
  res.value |> string.length() |> should.equal(10)
}

pub fn make_redirect_uri_test() {
  // Given
  let assert Ok(u) = uri.parse("https://example.com/oauth2/?q=asdf")
  let response_type = oauth2.Code
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let client_id = oauth2.ClientId("client-id")
  let scope = ["scope1", "scope2"]
  let state = oauth2.State("state")
  let expected =
    uri.Uri(
      scheme: option.Some("https"),
      userinfo: option.None,
      host: option.Some("example.com"),
      port: option.None,
      path: "/oauth2/",
      query: option.Some(
        "state=state&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&response_type=code&client_id=client-id&scope=scope1%20scope2",
      ),
      fragment: option.None,
    )

  // When
  let res =
    oauth2.make_redirect_uri(
      u,
      response_type,
      option.Some(redirect_uri),
      client_id,
      scope,
      option.Some(state),
    )

  // Then
  res |> should.equal(expected)
}

pub fn to_http_request_for_auth_basic_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/?q=asdf")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    oauth2.AuthorizationCodeGrantTokenRequest(
      server,
      oauth2.ClientSecretBasic(oauth2.ClientId("test"), oauth2.Secret("test")),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
        #("authentication", "Basic dGVzdDp0ZXN0"),
      ],
      body: "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&client_id=test&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = oauth2.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_auth_basic_with_expired_secret_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/?q=asdf")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let secret =
    oauth2.SecretWithExpiration(
      "test",
      timestamp.system_time() |> timestamp.add(duration.hours(-10)),
    )
  let token_request =
    oauth2.AuthorizationCodeGrantTokenRequest(
      server,
      oauth2.ClientSecretBasic(oauth2.ClientId("test"), secret),
      option.Some(redirect_uri),
      "asdf",
    )

  // When
  let res = oauth2.to_http_request(token_request)

  // Then
  res |> should.equal(Error(oauth2.SecretExpired))
}

pub fn to_http_request_for_auth_post_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/?q=asdf")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    oauth2.AuthorizationCodeGrantTokenRequest(
      server,
      oauth2.ClientSecretPost(oauth2.ClientId("test"), oauth2.Secret("test")),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [#("content-type", "application/x-www-form-urlencoded")],
      body: "client_secret=test&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&client_id=test&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = oauth2.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_auth_post_with_expired_secret_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/?q=asdf")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let secret =
    oauth2.SecretWithExpiration(
      "test",
      timestamp.system_time() |> timestamp.add(duration.hours(-10)),
    )
  let token_request =
    oauth2.AuthorizationCodeGrantTokenRequest(
      server,
      oauth2.ClientSecretPost(oauth2.ClientId("test"), secret),
      option.Some(redirect_uri),
      "asdf",
    )

  // When
  let res = oauth2.to_http_request(token_request)

  // Then
  res |> should.equal(Error(oauth2.SecretExpired))
}

pub fn to_http_request_for_public_auth_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/?q=asdf")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    oauth2.AuthorizationCodeGrantTokenRequest(
      server,
      oauth2.PublicAuthentication(oauth2.ClientId("test")),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [#("content-type", "application/x-www-form-urlencoded")],
      body: "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&client_id=test&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = oauth2.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}
