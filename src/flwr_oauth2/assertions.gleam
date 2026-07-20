import flwr_oauth2 as oauth
import gleam/dict
import gleam/http/request
import gleam/option
import gleam/uri

pub type AssertionAuthorizationGrantRequest {
  AssertionAuthorizationGrantRequest(
    token_endpoint: uri.Uri,
    assertion: String,
    grant_type: String,
    authentication: option.Option(oauth.ClientAuthentication),
    scope: oauth.Scope,
  )
}

pub type PresetAssertionAuthorizationGrantRequest {
  PresetAssertionAuthorizationGrantRequest(
    token_endpoint: uri.Uri,
    assertion: String,
    authentication: option.Option(oauth.ClientAuthentication),
    scope: oauth.Scope,
  )
}

pub fn to_authentication(
  client_id: oauth.ClientId,
  client_assertion: String,
  client_assertion_type,
) {
  oauth.ClientAssertion(client_id:, client_assertion:, client_assertion_type:)
}

pub fn to_http_request(
  grant: AssertionAuthorizationGrantRequest,
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

fn grant_modifier(
  req: oauth.UrlEncRequest,
  grant: AssertionAuthorizationGrantRequest,
) -> Result(oauth.UrlEncRequest, oauth.RequestError) {
  req.body
  |> dict.from_list()
  |> dict.insert("grant_type", grant.grant_type)
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
