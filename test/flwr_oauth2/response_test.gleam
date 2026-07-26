import flwr_oauth2/response as oauth_response
import gleam/http/response
import gleam/option
import gleeunit/should

pub fn parse_token_response_with_valid_response_all_fields_test() {
  // Given
  let json =
    "{\"access_token\": \"2YotnFZFEjr1zCsicMWpAA\", \"token_type\": \"example\", \"expires_in\": 3600, \"refresh_token\": \"tGzv3JOkF0XG5Qx2TlKWIA\", \"scope\": \"new scope\", \"ignore\": \"ignore\"}"
  let resp = response.Response(status: 200, headers: [], body: json)
  let expected =
    oauth_response.AccessTokenResponse(
      access_token: "2YotnFZFEjr1zCsicMWpAA",
      token_type: "example",
      expires_in: option.Some(3600),
      refresh_token: option.Some("tGzv3JOkF0XG5Qx2TlKWIA"),
      scope: ["new", "scope"],
    )

  // When
  let res = oauth_response.parse_token_response(resp)

  // Then
  res |> should.equal(Ok(expected))
}

pub fn parse_token_response_with_valid_response_optional_fields_missing_test() {
  // Given
  let json =
    "{\"access_token\": \"2YotnFZFEjr1zCsicMWpAA\", \"token_type\": \"example\", \"ignore\": \"ignore\"}"
  let resp = response.Response(status: 200, headers: [], body: json)
  let expected =
    oauth_response.AccessTokenResponse(
      access_token: "2YotnFZFEjr1zCsicMWpAA",
      token_type: "example",
      expires_in: option.None,
      refresh_token: option.None,
      scope: [],
    )

  // When
  let res = oauth_response.parse_token_response(resp)

  // Then
  res |> should.equal(Ok(expected))
}

pub fn parse_token_response_with_error_response_test() {
  // Given
  let json =
    "{\"error\": \"invalid_request\", \"error_description\": \"Invalid Request\", \"error_uri\": \"https://example.com\"}"
  let resp = response.Response(status: 400, headers: [], body: json)
  let expected =
    oauth_response.ErrorResponse(
      status: 400,
      error: "invalid_request",
      error_description: option.Some("Invalid Request"),
      error_uri: option.Some("https://example.com"),
    )

  // When
  let res = oauth_response.parse_token_response(resp)

  // Then
  res |> should.equal(Error(expected))
}
