import flwr_oauth2/bearer_token.{BearerErrorResponse}
import flwr_oauth2/response
import gleam/http/request
import gleam/http/response as http_response
import gleam/option.{Some}
import gleam/uri
import gleeunit/should

pub fn attach_bearer_token_header_test() {
  // Given
  let token =
    response.AccessTokenResponse("token", "Bearer", Some(3600), option.None, [])
  let req = request.new()
  let expected =
    request.new()
    |> request.set_header("Authorization", "Bearer token")

  // When
  let res = bearer_token.attach_bearer_token_header(req, token)

  // Then
  res |> should.equal(expected)
}

pub fn attach_bearer_token_to_body_test() {
  // Given
  let token =
    response.AccessTokenResponse("token", "Bearer", Some(3600), option.None, [])
  let req = request.new() |> request.set_body([#("some", "body")])
  let expected =
    request.new()
    |> request.set_body([#("access_token", "token"), #("some", "body")])

  // When
  let res = bearer_token.attach_access_token_to_body(req, token)

  // Then
  res |> should.equal(expected)
}

pub fn attach_bearer_token_to_query_params_test() {
  // Given
  let token =
    response.AccessTokenResponse("token", "Bearer", Some(3600), option.None, [])
  let req =
    request.new()
    |> request.set_query([#("some", "query")])
  let expected =
    request.new()
    |> request.set_query([#("access_token", "token"), #("some", "query")])

  // When
  let res = bearer_token.attach_access_token_to_query_parameters(req, token)

  // Then
  res |> should.equal(expected)
}

pub fn parse_bearer_error_response_test() {
  // Given
  let error_uri = uri.parse("https://example.com") |> option.from_result()
  let resp =
    http_response.new(401)
    |> http_response.set_header(
      "WWW-Authenticate",
      "bEARER realm=\"dev\",
      SCOPE=\"read write\",
      error=\"invalid_request\",
      error_description=\"asdf\",
      error_uri=\"https://example.com\",
      Basic realm=\"dev\"",
    )

  // When
  let res = bearer_token.parse_bearer_error_response(resp)

  // Then
  res
  |> should.be_ok()
  |> should.equal([
    BearerErrorResponse(
      realm: Some("dev"),
      scope: ["read", "write"],
      error: Some("invalid_request"),
      error_description: Some("asdf"),
      error_uri:,
    ),
  ])
}

pub fn parse_invalid_bearer_error_response_test() {
  // Given
  let resp =
    http_response.new(401)
    |> http_response.set_header("WWW-Authenticate", "Bearer realm=")

  // When
  let res = bearer_token.parse_bearer_error_response(resp)

  // Then
  res |> should.be_error()
}
