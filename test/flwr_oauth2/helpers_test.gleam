import flwr_oauth2/helpers
import gleam/http/response
import gleeunit/should

pub fn generate_random_string_should_produce_different_strings_test() {
  // Given
  let length = 10

  // When
  let res1 = helpers.generate_random_string("asdf", length)
  let res2 = helpers.generate_random_string("asdf", length)

  // Then
  res1 |> should.not_equal(res2)
}

pub fn verify_content_type_test() {
  // Given
  let resp =
    response.new(200)
    |> response.set_header("Content-Type", "application/json; charset: UTF-8")

  // When
  let res =
    helpers.verify_content_type(response: resp, expected: "application/json")

  // Then
  res |> should.be_ok()
}

pub fn verify_content_type_returns_error_test() {
  // Given
  let resp =
    response.new(200)
    |> response.set_header("Content-Type", "application/jsonld; charset: UTF-8")

  // When
  let res =
    helpers.verify_content_type(response: resp, expected: "application/json")

  // Then
  res |> should.be_error() |> should.equal("application/jsonld; charset: UTF-8")
}
