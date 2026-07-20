//// This module aims to implement [RFC7523](https://datatracker.ietf.org/doc/html/rfc7523) JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants.
//// For more infomation on the Authorization Assertion Grant Type see [RFC7521](https://datatracker.ietf.org/doc/html/rfc7521).

import flwr_oauth2 as oauth
import gleam/dict
import gleam/http/request
import gleam/option
import gleam/uri

const grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"

const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

pub type JwtAuthorizationGrantRequest {
  JwtAuthorizationGrantRequest(
    token_endpoint: uri.Uri,
    assertion: String,
    authentication: option.Option(oauth.ClientAuthentication),
    scope: oauth.Scope,
  )
}

pub fn to_http_request(
  grant: JwtAuthorizationGrantRequest,
) -> Result(request.Request(String), oauth.RequestError) {
  let grant_modifier: oauth.RequestModifier = grant_modifier(_, grant)
  oauth.ClientCredentialsGrantTokenRequest(
    token_endpoint: grant.token_endpoint,
    authentication: oauth.PublicAuthentication(oauth.ClientId("")),
    scope: grant.scope,
  )
  |> oauth.to_http_request_with_custom_authentication([
    grant_modifier,
    authorization_setter(grant.authentication),
  ])
}

pub fn to_authentication(client_id: oauth.ClientId, client_assertion: String) {
  oauth.ClientAssertion(client_id:, client_assertion:, client_assertion_type:)
}

fn grant_modifier(
  req: oauth.UrlEncRequest,
  grant: JwtAuthorizationGrantRequest,
) -> Result(oauth.UrlEncRequest, oauth.RequestError) {
  req.body
  |> dict.from_list()
  |> dict.insert("grant_type", grant_type)
  |> dict.insert("assertion", grant.assertion)
  |> dict.to_list()
  |> request.set_body(req, _)
  |> Ok
}

fn authorization_setter(authorization) -> oauth.RequestModifier {
  authorization
  |> option.map(oauth.authorization_setter)
  |> option.unwrap(fn(req: oauth.UrlEncRequest) -> Result(
    oauth.UrlEncRequest,
    oauth.RequestError,
  ) {
    Ok(req)
  })
}
