import flwr_oauth2/pkce
import gleam/string
import gleeunit/should

pub fn new_should_create_a_random_verifier_test() {
  // Given
  // When
  let res = pkce.new()
  // Then
  res.value
  |> string.length()
  |> should.equal(128)
}

pub fn to_challenge_creates_valid_challenge_test() {
  // Given
  let verifier = pkce.Verifier("E1remVZK4EfLviZnCjFBuhvx2WORWbJye1zjpzaNzQw")
  let expected = pkce.Challenge("tXo4GOf-1dCfRSZO1-1jigdkNsPuonbIZD6N-j9Eqbk")

  // When
  let challenge = pkce.to_challenge(verifier)

  // Then
  challenge |> should.equal(expected)
}
