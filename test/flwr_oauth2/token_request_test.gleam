import flwr_oauth2/authentication
import flwr_oauth2/common
import flwr_oauth2/token_request
import gleam/http
import gleam/http/request
import gleam/option
import gleam/time/duration
import gleam/time/timestamp
import gleam/uri
import gleeunit/should

pub fn to_http_request_for_auth_basic_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    token_request.AuthorizationCodeGrantTokenRequest(
      server,
      authentication.ClientSecretBasic(
        common.ClientId("test"),
        common.Secret("test"),
      ),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
        #("authorization", "Basic dGVzdDp0ZXN0"),
      ],
      body: "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_auth_basic_pads_correctly_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    token_request.AuthorizationCodeGrantTokenRequest(
      server,
      authentication.ClientSecretBasic(
        common.ClientId("II"),
        common.Secret("I"),
      ),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
        #("authorization", "Basic SUk6SQ=="),
      ],
      body: "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_auth_basic_with_expired_secret_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let secret =
    common.SecretWithExpiration(
      "test",
      timestamp.system_time() |> timestamp.add(duration.hours(-10)),
    )
  let token_request =
    token_request.AuthorizationCodeGrantTokenRequest(
      server,
      authentication.ClientSecretBasic(common.ClientId("test"), secret),
      option.Some(redirect_uri),
      "asdf",
    )

  // When
  let res = token_request.to_http_request(token_request)

  // Then
  res |> should.equal(Error(token_request.SecretExpired))
}

pub fn to_http_request_for_auth_post_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    token_request.AuthorizationCodeGrantTokenRequest(
      server,
      authentication.ClientSecretPost(
        common.ClientId("test"),
        common.Secret("test"),
      ),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [#("content-type", "application/x-www-form-urlencoded")],
      body: "client_id=test&client_secret=test&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_auth_post_with_expired_secret_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/asdf")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let secret =
    common.SecretWithExpiration(
      "test",
      timestamp.system_time() |> timestamp.add(duration.hours(-10)),
    )
  let token_request =
    token_request.AuthorizationCodeGrantTokenRequest(
      server,
      authentication.ClientSecretPost(common.ClientId("test"), secret),
      option.Some(redirect_uri),
      "asdf",
    )

  // When
  let res = token_request.to_http_request(token_request)

  // Then
  res |> should.equal(Error(token_request.SecretExpired))
}

pub fn to_http_request_for_public_auth_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    token_request.AuthorizationCodeGrantTokenRequest(
      server,
      authentication.PublicAuthentication(common.ClientId("test")),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [#("content-type", "application/x-www-form-urlencoded")],
      body: "client_id=test&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_resource_owner_request_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let token_request =
    token_request.ResourceOwnerCredentialsGrantTokenRequest(
      server,
      authentication.ClientSecretBasic(
        common.ClientId("test"),
        common.Secret("test"),
      ),
      "username",
      "password",
      ["scope1"],
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
        #("authorization", "Basic dGVzdDp0ZXN0"),
      ],
      body: "scope=scope1&grant_type=password&username=username&password=password",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_client_credentials_request_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let token_request =
    token_request.ClientCredentialsGrantTokenRequest(
      server,
      authentication.ClientSecretBasic(
        common.ClientId("test"),
        common.Secret("test"),
      ),
      ["scope1"],
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
        #("authorization", "Basic dGVzdDp0ZXN0"),
      ],
      body: "scope=scope1&grant_type=client_credentials",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_client_credentials_request_without_scopes_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let token_request =
    token_request.ClientCredentialsGrantTokenRequest(
      server,
      authentication.ClientSecretBasic(
        common.ClientId("test"),
        common.Secret("test"),
      ),
      [],
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
        #("authorization", "Basic dGVzdDp0ZXN0"),
      ],
      body: "grant_type=client_credentials",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}

pub fn to_http_request_for_auth_assertion_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    token_request.AuthorizationCodeGrantTokenRequest(
      server,
      authentication.ClientAssertion(
        common.ClientId("test"),
        "assertion",
        "assertion_type",
      ),
      option.Some(redirect_uri),
      "asdf",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
      ],
      body: "client_id=test&client_assertion_type=assertion_type&client_assertion=assertion&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&code=asdf",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = token_request.to_http_request(token_request)
  // Then
  res |> should.equal(Ok(expected))
}
