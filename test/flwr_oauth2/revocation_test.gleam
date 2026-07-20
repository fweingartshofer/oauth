import flwr_oauth2 as oauth
import flwr_oauth2/revocation
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/option
import gleam/uri
import gleeunit/should

pub fn to_http_request_with_revocation_of_access_token_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com")
  let revocation_request =
    revocation.RevocationRequest(
      server,
      "token",
      option.Some(revocation.AccessToken),
      oauth.PublicAuthentication(oauth.ClientId("client-id")),
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
      ],
      body: "token_type_hint=access_token&client_id=client-id&token=token",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "",
      query: option.None,
    )

  // When
  let res = revocation.to_http_request(revocation_request)

  // Then
  res
  |> should.be_ok()
  |> should.equal(expected)
}

pub fn parse_revocation_response_with_success_response_test() {
  // Given
  let resp = response.new(200) |> response.set_body("ignored body")

  // When
  let res = revocation.parse_revocation_response(resp)

  // Then
  res
  |> should.be_ok()
  |> should.equal(revocation.RevocationResponse)
}

pub fn parse_revocation_response_with_error_response_test() {
  // Given
  let expected =
    oauth.ErrorResponse(
      400,
      "unsupported_token_type",
      option.Some("This token type is not supported"),
      option.Some("https://example.com"),
    )
  let body =
    "{\"error\": \"unsupported_token_type\", \"error_description\": \"This token type is not supported\", \"error_uri\": \"https://example.com\"}"
  let resp = response.new(400) |> response.set_body(body)

  // When
  let res = revocation.parse_revocation_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(expected)
}
