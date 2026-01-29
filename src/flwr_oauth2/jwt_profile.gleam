//// This module aims to implement [RFC7523](https://datatracker.ietf.org/doc/html/rfc7523) JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants.
//// For more infomation on the Authorization Assertion Grant Type see [RFC7521](https://datatracker.ietf.org/doc/html/).

import flwr_oauth2 as oauth
import gleam/http/request
import gleam/option
import gleam/uri

const grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"

pub type JwtAuthorizationGrantRequest {
  JwtAuthorizationGrantRequest(
    token_endpoint: uri.Uri,
    assertion: String,
    authorization: option.Option(oauth.ClientAuthentication),
    scope: oauth.Scope,
  )
}

pub fn to_http_request(
  grant: JwtAuthorizationGrantRequest,
) -> Result(request.Request(String), oauth.RequestError) {
  [#("grant_type", grant_type), #("assertion", grant.assertion)]
  |> oauth.add_scope(grant.scope)
  |> oauth.setup_request(
    endpoint: grant.token_endpoint,
    body: _,
    client_auth: grant.authorization |> authorization_setter(),
  )
}

fn authorization_setter(authorization) {
  authorization
  |> option.map(oauth.authorization_setter)
  |> option.unwrap(
    oauth.AuthorizationSetter(fn(req: oauth.UrlEncRequest) -> Result(
      oauth.UrlEncRequest,
      oauth.RequestError,
    ) {
      Ok(req)
    }),
  )
}
