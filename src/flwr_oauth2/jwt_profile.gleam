//// This module aims to implement [RFC7523 ](https://datatracker.ietf.org/doc/html/rfc7523) JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants.

import flwr_oauth2 as oauth
import gleam/http/request
import gleam/option
import gleam/uri

const grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"

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
  let body =
    [#("grant_type", grant_type), #("assertion", grant.assertion)]
    |> oauth.add_scope(grant.scope)
  oauth.setup_request(
    endpoint: grant.token_endpoint,
    body: body,
    client_auth: grant.authentication,
  )
}
