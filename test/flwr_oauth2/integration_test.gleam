import envoy
import flwr_oauth2 as oauth2
import flwr_oauth2/helpers
import gleam/bool
import gleam/hackney
import gleam/io
import gleam/result
import gleam/uri
import gleeunit/should

pub fn client_credential_grant_with_http_port_retrieves_tokens_test() {
  use _ <- run_integration_tests()
  // Given
  let assert Ok(server) =
    uri.parse(
      "http://localhost:8080/realms/OAuth/protocol/openid-connect/token",
    )

  let token_request =
    oauth2.ClientCredentialsGrantTokenRequest(
      server,
      oauth2.ClientSecretPost(
        oauth2.ClientId("credentials-client"),
        oauth2.Secret("client-secret"),
      ),
      ["openid"],
    )
  let assert Ok(req) = oauth2.to_http_request(token_request)

  // When
  let res = hackney.send(req)

  // Then
  res
  |> should.be_ok()
  |> oauth2.parse_token_response()
  |> should.be_ok()
}

pub fn client_credential_grant_with_authorization_basic_retrieves_tokens_test() {
  use _ <- run_integration_tests()
  // Given
  let assert Ok(server) =
    uri.parse(
      "http://localhost:8080/realms/OAuth/protocol/openid-connect/token",
    )

  let token_request =
    oauth2.ClientCredentialsGrantTokenRequest(
      server,
      oauth2.ClientSecretBasic(
        oauth2.ClientId("credentials-client"),
        oauth2.Secret("client-secret"),
      ),
      ["openid"],
    )
  let assert Ok(req) = oauth2.to_http_request(token_request)

  // When
  let res = hackney.send(req)

  // Then
  res
  |> should.be_ok()
  |> oauth2.parse_token_response()
  |> should.be_ok()
}

fn run_integration_tests(integration_test: fn(Nil) -> b) {
  let result =
    envoy.get("ENABLE_INTEGRATION_TESTS")
    |> result.map(fn(_) { True })
    |> result.map_error(fn(_) { False })
    |> helpers.unwrap_both()
  let wrapper = fn() {
    integration_test(Nil)
    Nil
  }
  bool.lazy_guard(result, wrapper, fn() {
    io.println_error("Skipping integration tests")
  })
}
