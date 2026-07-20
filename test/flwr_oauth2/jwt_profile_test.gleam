import flwr_oauth2
import flwr_oauth2/jwt_profile
import gleam/http
import gleam/http/request
import gleam/option
import gleam/uri
import gleeunit/should

pub fn to_http_request_test() {
  // Given
  let assert Ok(endpoint) = uri.parse("https://example.com")
  let jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
  let req =
    jwt_profile.JwtAuthorizationGrantRequest(endpoint, jwt, option.None, [])
  let expected =
    request.Request(
      method: http.Post,
      headers: [
        #("content-type", "application/x-www-form-urlencoded"),
      ],
      body: "assertion="
        <> jwt
        <> "&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
      scheme: http.Https,
      host: "example.com",
      port: option.None,
      path: "",
      query: option.None,
    )

  // When
  let resp = jwt_profile.to_http_request(req)

  // Then
  resp
  |> should.be_ok()
  |> should.equal(expected)
}

pub fn to_authentication_test() {
  // Given
  let expected =
    flwr_oauth2.ClientAssertion(
      client_id: flwr_oauth2.ClientId("test"),
      client_assertion: "jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    )

  // When
  let res = jwt_profile.to_authentication(flwr_oauth2.ClientId("test"), "jwt")

  // Then
  res |> should.equal(expected)
}
