import birdie
import flwr_oauth2
import flwr_oauth2/assertions
import flwr_oauth2/helpers
import flwr_oauth2/saml_profile
import gleam/option
import gleam/uri
import gleeunit/should

pub fn to_http_request_test() {
  let assert Ok(endpoint) = uri.parse("https://example.com")
  let saml_assertion = "PHN...="
  let req =
    assertions.PresetAssertionAuthorizationGrantRequest(
      endpoint,
      saml_assertion,
      option.None,
      [],
    )

  let assert Ok(resp) = saml_profile.to_http_request(req)

  resp
  |> helpers.request_to_string()
  |> birdie.snap(title: "SAML Profile to_http_request Test")
}

pub fn to_authentication_test() {
  // Given
  let expected =
    flwr_oauth2.ClientAssertion(
      client_id: flwr_oauth2.ClientId("test"),
      client_assertion: "saml",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
    )

  // When
  let res = saml_profile.to_authentication(flwr_oauth2.ClientId("test"), "saml")

  // Then
  res |> should.equal(expected)
}
