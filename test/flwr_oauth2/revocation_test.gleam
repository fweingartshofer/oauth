import flwr_oauth2 as oauth
import flwr_oauth2/revocation
import glacier
import glacier/should
import gleam/http
import gleam/http/request
import gleam/option
import gleam/uri

pub fn main() -> Nil {
  glacier.main()
}

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
      body: "client_id=client-id&token_type_hint=access_token&token=token",
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
