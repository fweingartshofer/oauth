import birdie
import flwr_oauth2
import flwr_oauth2/authorization_grant as oauth
import flwr_oauth2/pkce
import gleam/http/request
import gleam/option
import gleam/string
import gleam/uri
import gleeunit/should

pub fn random_state32_test() {
  // Given
  // When
  let res = oauth.random_state32()

  // Then
  res.value |> string.length() |> should.equal(32)
}

pub fn random_state_test() {
  // Given
  // When
  let res = oauth.random_state(10)

  // Then
  res.value |> string.length() |> should.equal(10)
}

pub fn make_redirect_uri_test() {
  // Given
  let assert Ok(u) = uri.parse("https://example.com/oauth2/?q=asdf")
  let response_type = oauth.Code
  let redirect_uri =
    uri.parse("http://localhost:8080/callback") |> option.from_result
  let client_id = flwr_oauth2.ClientId("client-id")
  let scope = ["scope1", "scope2"]
  let state = option.Some(oauth.State("state"))
  let redirect_config =
    oauth.AuthorizationCodeGrantRequest(
      u,
      response_type,
      redirect_uri,
      client_id,
      scope,
      state,
      option.Some("asdf"),
      option.Some(oauth.S256),
    )

  // When
  let res = oauth.make_redirect_uri(redirect_config)

  // Then
  res |> uri.to_string() |> birdie.snap(title: "Make Redirect URI Test")
}

pub fn parse_authorization_error_response_test() {
  // Given
  let req =
    request.new()
    |> request.set_query([
      #("error", "invalid_request"),
      #("error_description", "error description"),
      #("error_uri", "https://example.com/error"),
      #("state", "1234"),
    ])

  // When
  let assert Ok(res) = oauth.parse_authorization_response(req)

  // Then
  res
  |> oauth.to_string()
  |> birdie.snap(title: "Parse Authorization Error Response Test")
}

pub fn parse_authorization_error_response_invalid_uri_test() {
  // Given
  let req =
    request.new()
    |> request.set_query([
      #("error", "invalid_request"),
      #("error_description", "error description"),
      #("error_uri", "://01234"),
      #("state", "1234"),
    ])

  // When
  let assert Error(res) = oauth.parse_authorization_response(req)

  // Then
  res
  |> oauth.error_to_string()
  |> birdie.snap(
    title: "Parse Authorization Error Response with Invalid URI returns ParseError Test",
  )
}

pub fn parse_authorization_code_response_test() {
  // Given
  let req =
    request.new()
    |> request.set_query([
      #("code", "auth_code"),
      #("state", "asdf"),
    ])

  // When
  let assert Ok(res) = oauth.parse_authorization_response(req)

  // Then
  res
  |> oauth.to_string()
  |> birdie.snap(title: "Parse Authorization Code Response Test")
}

pub fn parse_empty_authorization_response_test() {
  // Given
  let req =
    request.new()
    |> request.set_query([])

  // When
  let assert Error(res) = oauth.parse_authorization_response(req)

  // Then
  res
  |> oauth.error_to_string()
  |> birdie.snap(title: "Parse Empty Authorization Response Test")
}

pub fn parse_authorization_implicit_response_test() {
  // Given
  let req =
    request.new()
    |> request.set_query([
      #("access_token", "token"),
      #("token_type", "Bearer"),
      #("expires_in", "3600"),
      #("scope", "read write"),
      #("state", "asdf"),
    ])

  // When
  let assert Ok(res) = oauth.parse_authorization_response(req)

  // Then
  res
  |> oauth.to_string()
  |> birdie.snap(title: "Parse Authorization Implicit Response Test")
}

pub fn parse_authorization_implicit_response_without_token_type_test() {
  // Given
  let req =
    request.new()
    |> request.set_query([
      #("access_token", "token"),
      #("expires_in", "3600"),
      #("scope", "read write"),
      #("state", "asdf"),
    ])

  // When
  let assert Error(res) = oauth.parse_authorization_response(req)

  // Then
  res
  |> oauth.error_to_string()
  |> birdie.snap(
    title: "Parse Authorization Implicit Response without Token Type Test",
  )
}

pub fn parse_authorization_implicit_response_with_invalid_expires_in_test() {
  // Given
  let req =
    request.new()
    |> request.set_query([
      #("access_token", "token"),
      #("token_type", "Bearer"),
      #("expires_in", "string"),
      #("scope", "read write"),
      #("state", "asdf"),
    ])

  // When
  let assert Error(res) = oauth.parse_authorization_response(req)

  // Then
  res
  |> oauth.error_to_string()
  |> birdie.snap(
    title: "Parse Authorization Implicit Response with Invalid expires_in Test",
  )
}

pub fn to_token_request_test() {
  // Given
  let response =
    oauth.CodeGrantResponse(option.Some(oauth.State("state")), "code")
  let assert Ok(origin) = uri.parse("https://original-uri.com")
  let assert Ok(token_endpoint) = uri.parse("https://localhost:3000")

  // When
  let assert Ok(res) =
    oauth.to_token_request(
      response,
      token_endpoint,
      flwr_oauth2.ClientSecretPost(
        flwr_oauth2.ClientId("client-id"),
        flwr_oauth2.Secret("secret"),
      ),
      option.Some(origin),
    )
  // Then
  res
  |> flwr_oauth2.to_string_token_request()
  |> birdie.snap("to_token_request creates valid token request")
}

pub fn to_token_request_with_invalid_response_test() {
  // Given
  let response =
    oauth.ImplicitGrantResponse(
      option.Some(oauth.State("state")),
      flwr_oauth2.AccessTokenResponse(
        "access_token",
        "Bearer",
        option.None,
        option.None,
        [],
      ),
    )
  let assert Ok(origin) = uri.parse("https://original-uri.com")
  let assert Ok(token_endpoint) = uri.parse("https://localhost:3000")

  // When
  let res =
    oauth.to_token_request(
      response,
      token_endpoint,
      flwr_oauth2.ClientSecretPost(
        flwr_oauth2.ClientId("client-id"),
        flwr_oauth2.Secret("secret"),
      ),
      option.Some(origin),
    )
  // Then
  res |> should.be_error()
}

pub fn to_token_request_with_pkce_verifier_test() {
  // Given
  let response =
    oauth.CodeGrantResponse(option.Some(oauth.State("state")), "code")
  let assert Ok(origin) = uri.parse("https://original-uri.com")
  let assert Ok(token_endpoint) = uri.parse("https://localhost:3000")

  // When
  let assert Ok(res) =
    oauth.to_token_request_with_pkce_verifier(
      response,
      token_endpoint,
      flwr_oauth2.ClientSecretPost(
        flwr_oauth2.ClientId("client-id"),
        flwr_oauth2.Secret("secret"),
      ),
      option.Some(origin),
      pkce.Verifier("verifier"),
    )
  // Then
  res
  |> pkce.to_string()
  |> birdie.snap(
    "to_token_request_with_pkce_verifier creates valid token request",
  )
}

pub fn to_token_request_with_pkce_verifier_with_invalid_response_test() {
  // Given
  let response =
    oauth.ImplicitGrantResponse(
      option.Some(oauth.State("state")),
      flwr_oauth2.AccessTokenResponse(
        "access_token",
        "Bearer",
        option.None,
        option.None,
        [],
      ),
    )
  let assert Ok(origin) = uri.parse("https://original-uri.com")
  let assert Ok(token_endpoint) = uri.parse("https://localhost:3000")

  // When
  let res =
    oauth.to_token_request_with_pkce_verifier(
      response,
      token_endpoint,
      flwr_oauth2.ClientSecretPost(
        flwr_oauth2.ClientId("client-id"),
        flwr_oauth2.Secret("secret"),
      ),
      option.Some(origin),
      pkce.Verifier("verifier"),
    )
  // Then
  res |> should.be_error()
}
