//// This module aims to implement [RFC7522](https://datatracker.ietf.org/doc/html/rfc7522) Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 for OAuth 2.0 Client Authentication and Authorization Grants and [RFC7523](https://datatracker.ietf.org/doc/html/rfc7523) JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants.
//// For more infomation on the Authorization Assertion Grant Type see [RFC7521](https://datatracker.ietf.org/doc/html/rfc7521).

import flwr_oauth2/authentication
import flwr_oauth2/common
import flwr_oauth2/helpers
import flwr_oauth2/token_request
import gleam/bool
import gleam/http/request
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

pub type AssertionAuthorizationGrantRequest {
  AssertionAuthorizationGrantRequest(
    token_endpoint: uri.Uri,
    assertion: String,
    grant_type: String,
    authentication: option.Option(authentication.ClientAuthentication),
    scope: common.Scope,
  )
}

pub type PresetAssertionAuthorizationGrantRequest {
  PresetAssertionAuthorizationGrantRequest(
    token_endpoint: uri.Uri,
    assertion: String,
    authentication: option.Option(authentication.ClientAuthentication),
    scope: common.Scope,
  )
}

const saml_grant_type = "urn:ietf:params:oauth:grant-type:saml2-bearer"

const saml_client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"

pub fn to_saml_http_request(
  grant: PresetAssertionAuthorizationGrantRequest,
) -> Result(request.Request(String), token_request.RequestError) {
  let PresetAssertionAuthorizationGrantRequest(
    token_endpoint:,
    assertion:,
    authentication:,
    scope:,
  ) = grant
  AssertionAuthorizationGrantRequest(
    token_endpoint:,
    assertion:,
    grant_type: saml_grant_type,
    authentication:,
    scope:,
  )
  |> to_http_request
}

pub fn to_saml_authentication(
  client_id: common.ClientId,
  client_assertion: String,
) {
  to_authentication(client_id, client_assertion, saml_client_assertion_type)
}

const jwt_grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"

const jwt_client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

pub fn to_jwt_http_request(
  grant: PresetAssertionAuthorizationGrantRequest,
) -> Result(request.Request(String), token_request.RequestError) {
  let PresetAssertionAuthorizationGrantRequest(
    token_endpoint:,
    assertion:,
    authentication:,
    scope:,
  ) = grant
  AssertionAuthorizationGrantRequest(
    token_endpoint:,
    assertion:,
    grant_type: jwt_grant_type,
    authentication:,
    scope:,
  )
  |> to_http_request
}

pub fn to_jwt_authentication(
  client_id: common.ClientId,
  client_assertion: String,
) {
  to_authentication(client_id, client_assertion, jwt_client_assertion_type)
}

pub fn to_authentication(
  client_id: common.ClientId,
  client_assertion: String,
  client_assertion_type,
) {
  authentication.ClientAssertion(
    client_id:,
    client_assertion:,
    client_assertion_type:,
  )
}

pub fn to_http_request(
  grant: AssertionAuthorizationGrantRequest,
) -> Result(request.Request(String), token_request.RequestError) {
  let scope = {
    use <- bool.guard(when: list.is_empty(grant.scope), return: option.None)
    let scope = grant.scope |> string.join(" ")
    #("scope", scope) |> option.Some
  }
  let body =
    [
      #("grant_type", grant.grant_type),
      #("assertion", grant.assertion),
    ]
    |> helpers.add_if_present(scope)
  let auth_mods = case grant.authentication {
    option.Some(auth) -> [token_request.authorization_setter(auth)]
    option.None -> []
  }
  token_request.setup_request(endpoint: grant.token_endpoint, body: body)
  |> result.try(token_request.apply_modifiers(_, auth_mods))
  |> result.map(token_request.request_body_to_string)
}
