import birdie
import flwr_oauth2/bearer_token
import flwr_oauth2/common
import flwr_oauth2/response.{AuthorizationServerError} as _
import flwr_oauth2/revocation
import flwr_oauth2/test_utils
import flwr_oauth2/token_introspection.{BearerTokenError}
import gleam/http/response
import gleam/option.{None, Some}
import gleam/time/timestamp
import gleam/uri
import gleeunit/should

pub fn to_http_request_test() {
  // Given
  let assert Ok(endpoint) = uri.parse("https://example.com")
  let req =
    token_introspection.IntrospectionRequest(
      endpoint:,
      token: "token",
      token_hint: Some(revocation.AccessToken),
    )

  // When
  let res = token_introspection.to_http_request(req)

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap("Token Introspection to http request test")
}

pub fn parse_intro_spection_response_with_invalid_bearer_token_test() {
  // Given
  let resp =
    response.new(401)
    |> response.set_header(
      "www-authenticate",
      "Bearer realm=\"dev\", error=\"invalid_token\"",
    )

  // When
  let res = token_introspection.parse_introspection_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    BearerTokenError([
      bearer_token.BearerErrorResponse(
        realm: Some("dev"),
        scope: [],
        error: Some("invalid_token"),
        error_description: None,
        error_uri: None,
      ),
    ]),
  )
}

pub fn parse_intro_spection_response_with_invalid_client_credentials_test() {
  // Given
  let resp =
    response.new(401)
    |> response.set_header("content-type", "application/json")
    |> response.set_body("{\"error\":\"invalid_client\"}")

  // When
  let res = token_introspection.parse_introspection_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    token_introspection.AuthorizationServerError(AuthorizationServerError(
      status: 401,
      error: "invalid_client",
      error_description: None,
      error_uri: None,
    )),
  )
}

pub fn parse_intro_spection_response_with_invalid_content_type_test() {
  // Given
  let resp =
    response.new(200)
    |> response.set_header("content-type", "application/xml")

  // When
  let res = token_introspection.parse_introspection_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    token_introspection.ParseError(common.UnsupportedContent("application/xml")),
  )
}

pub fn parse_intro_spection_response_with_invalid_status_test() {
  // Given
  let resp = response.new(500)

  // When
  let res = token_introspection.parse_introspection_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(token_introspection.InvalidStatus(500))
}

pub fn parse_intro_spection_response_test() {
  // Given
  let resp =
    response.new(200)
    |> response.set_body(
      "{\"active\":true,\"client_id\":\"l238j323ds-23ij4\",\"username\":\"jdoe\",\"scope\":\"read write dolphin\",\"sub\":\"Z5O3upPC88QrAjx00dis\",\"aud\":\"https://protected.example.net/resource\",\"iss\":\"https://server.example.com/\",\"exp\":1419356238,\"iat\":1419350238,\"extension_field\":\"twenty-seven\"}",
    )
  // When
  let res = token_introspection.parse_introspection_response(resp)

  // Then
  res
  |> should.be_ok()
  |> should.equal(token_introspection.IntrospectionResponse(
    active: True,
    scope: ["read", "write", "dolphin"],
    client_id: Some(common.ClientId("l238j323ds-23ij4")),
    username: Some("jdoe"),
    token_type: None,
    expires_at: Some(timestamp.from_unix_seconds(1_419_356_238)),
    issued_at: Some(timestamp.from_unix_seconds(1_419_350_238)),
    not_before: None,
    subject: Some("Z5O3upPC88QrAjx00dis"),
    audience: ["https://protected.example.net/resource"],
    issuer: Some("https://server.example.com/"),
    jti: None,
  ))
}

pub fn parse_intro_spection_response_for_inactive_client_for_multiple_audiences_test() {
  // Given
  let resp =
    response.new(200)
    |> response.set_body(
      "{\"active\":false,\"client_id\":\"l238j323ds-23ij4\",\"username\":\"jdoe\",\"scope\":\"read write dolphin\",\"sub\":\"Z5O3upPC88QrAjx00dis\",\"aud\":[\"https://protected.example.net/resource\", \"https://protected.example.net/resources\"],\"iss\":\"https://server.example.com/\",\"exp\":1419356238,\"iat\":1419350238,\"extension_field\":\"twenty-seven\"}",
    )
  // When
  let res = token_introspection.parse_introspection_response(resp)

  // Then
  res
  |> should.be_ok()
  |> should.equal(token_introspection.IntrospectionResponse(
    active: False,
    scope: ["read", "write", "dolphin"],
    client_id: Some(common.ClientId("l238j323ds-23ij4")),
    username: Some("jdoe"),
    token_type: None,
    expires_at: Some(timestamp.from_unix_seconds(1_419_356_238)),
    issued_at: Some(timestamp.from_unix_seconds(1_419_350_238)),
    not_before: None,
    subject: Some("Z5O3upPC88QrAjx00dis"),
    audience: [
      "https://protected.example.net/resource",
      "https://protected.example.net/resources",
    ],
    issuer: Some("https://server.example.com/"),
    jti: None,
  ))
}
