import flwr_oauth2/authentication
import flwr_oauth2/common
import flwr_oauth2/pkce
import gleam/http
import gleam/http/request
import gleam/option
import gleam/string
import gleam/uri
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

pub fn to_http_request_with_pkce_test() {
  // Given
  let assert Ok(server) = uri.parse("https://example.com/oauth2/")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080/callback")
  let token_request =
    pkce.AuthorizationCodeGrantTokenRequestWithPKCE(
      server,
      authentication.ClientSecretBasic(
        common.ClientId("test"),
        common.Secret("test"),
      ),
      option.Some(redirect_uri),
      "asdf",
      "code_verifier",
    )
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
        #("authorization", "Basic dGVzdDp0ZXN0"),
      ],
      body: "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&grant_type=authorization_code&code=asdf&code_verifier=code_verifier",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "/oauth2/",
      query: option.None,
    )

  // When
  let res = pkce.to_http_request(token_request)

  // Then
  res |> should.equal(Ok(expected))
}
