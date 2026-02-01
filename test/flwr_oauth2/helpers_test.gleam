import flwr_oauth2/helpers
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
