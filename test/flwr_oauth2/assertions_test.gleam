import birdie
import flwr_oauth2/assertions
import flwr_oauth2/authentication
import flwr_oauth2/common
import flwr_oauth2/test_utils
import gleam/option
import gleam/uri
import gleeunit/should

pub fn to_saml_http_request_test() {
  let assert Ok(endpoint) = uri.parse("https://example.com")
  let saml_assertion = "PHN...="
  let req =
    assertions.PresetAssertionAuthorizationGrantRequest(
      endpoint,
      saml_assertion,
      option.None,
      [],
    )

  let assert Ok(resp) = assertions.to_saml_http_request(req)

  resp
  |> test_utils.request_to_string()
  |> birdie.snap(title: "SAML Profile to_http_request Test")
}

pub fn to_saml_authentication_test() {
  // Given
  let expected =
    authentication.ClientAssertion(
      client_id: common.ClientId("test"),
      client_assertion: "saml",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
    )

  // When
  let res = assertions.to_saml_authentication(common.ClientId("test"), "saml")

  // Then
  res |> should.equal(expected)
}

pub fn to_jwt_http_request_test() {
  // Given
  let assert Ok(endpoint) = uri.parse("https://example.com")
  let jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
  let req =
    assertions.PresetAssertionAuthorizationGrantRequest(
      endpoint,
      jwt,
      option.None,
      [],
    )

  // When
  let assert Ok(resp) = assertions.to_jwt_http_request(req)

  // Then
  resp
  |> test_utils.request_to_string()
  |> birdie.snap(title: "JWT Profile to_http_request Test")
}

pub fn to_jwt_authentication_test() {
  // Given
  let expected =
    authentication.ClientAssertion(
      client_id: common.ClientId("test"),
      client_assertion: "jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    )

  // When
  let res = assertions.to_jwt_authentication(common.ClientId("test"), "jwt")

  // Then
  res |> should.equal(expected)
}
