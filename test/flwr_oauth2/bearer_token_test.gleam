import flwr_oauth2/bearer_token
import flwr_oauth2/response
import gleam/http/request
import gleam/option
import gleeunit/should

pub fn attach_bearer_token_header_test() {
  // Given
  let token =
    response.AccessTokenResponse(
      "token",
      "Bearer",
      option.Some(3600),
      option.None,
      [],
    )
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
    response.AccessTokenResponse(
      "token",
      "Bearer",
      option.Some(3600),
      option.None,
      [],
    )
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
    response.AccessTokenResponse(
      "token",
      "Bearer",
      option.Some(3600),
      option.None,
      [],
    )
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
