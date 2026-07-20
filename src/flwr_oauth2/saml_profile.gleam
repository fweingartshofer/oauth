//// This module aims to implement [RFC7522](https://datatracker.ietf.org/doc/html/rfc7522) Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 for OAuth 2.0 Client Authentication and Authorization Grants
//// For more infomation on the Authorization Assertion Grant Type see [RFC7521](https://datatracker.ietf.org/doc/html/rfc7521).

import flwr_oauth2 as oauth
import flwr_oauth2/assertions
import gleam/http/request

const grant_type = "urn:ietf:params:oauth:grant-type:saml2-bearer"

const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"

pub type SamlAuthorizationGrantRequest =
  assertions.PresetAssertionAuthorizationGrantRequest

pub fn to_http_request(
  grant: SamlAuthorizationGrantRequest,
) -> Result(request.Request(String), oauth.RequestError) {
  let assertions.PresetAssertionAuthorizationGrantRequest(
    token_endpoint:,
    assertion:,
    authentication:,
    scope:,
  ) = grant
  assertions.AssertionAuthorizationGrantRequest(
    token_endpoint:,
    assertion:,
    grant_type:,
    authentication:,
    scope:,
  )
  |> assertions.to_http_request
}

pub fn to_authentication(client_id: oauth.ClientId, client_assertion: String) {
  assertions.to_authentication(
    client_id,
    client_assertion,
    client_assertion_type,
  )
}
