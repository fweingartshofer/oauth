import flwr_oauth2 as oauth
import flwr_oauth2/helpers.{add_if_present}
import gleam/http/request
import gleam/http/response
import gleam/option
import gleam/uri

/// Defines a [RFC7009 Revocation Request](https://datatracker.ietf.org/doc/html/rfc7009#section-2.1).
pub type RevocationRequest {
  RevocationRequest(
    oauth_server: uri.Uri,
    token: String,
    token_type_hint: option.Option(TokenTypeHint),
    credentials: oauth.ClientAuthentication,
  )
}

/// Defines the type hint of a revocation request.
pub type TokenTypeHint {
  /// This defines that the revocation request is for an access token.
  /// The revocation of access tokens might not be supported by the OAuth 2.0 server
  AccessToken
  /// This defines that the revocation request is for a refresh token.
  /// The revocation of refresh tokens must be supported by the OAuth 2.0 server if it implements RFC 7009.
  RefreshToken
  /// An OAuth 2.0 server may define its own token type hints, use this constructor if this is the case.
  Other(hint: String)
}

pub type RevocationResponse {
  RevocationResponse
}

/// Formats a revocation request into a valid gleam http request.
pub fn to_http_request(
  revocation_request revocation_request: RevocationRequest,
) -> Result(request.Request(String), oauth.RequestError) {
  let hint = {
    use hint <- option.map(revocation_request.token_type_hint)
    let token_type = case hint {
      AccessToken -> "access_token"
      RefreshToken -> "refresh_token"
      Other(hint) -> hint
    }
    #("token_type_hint", token_type)
  }
  let body =
    [#("token", revocation_request.token)]
    |> add_if_present(hint)
  oauth.setup_request(
    endpoint: revocation_request.oauth_server,
    body: body,
    client_auth: revocation_request.credentials,
  )
}

/// Parses a revocation response as defined in [RFC7009](https://datatracker.ietf.org/doc/html/rfc7009#section-2.2).
/// If the response status is 200 the body is ignored.
/// Any other status code is an error response and will be parsed accordingly.
pub fn parse_revocation_response(
  revocation_response: response.Response(String),
) -> Result(RevocationResponse, oauth.ResponseError) {
  case revocation_response.status {
    200 -> Ok(RevocationResponse)
    _ -> oauth.parse_error_response(revocation_response) |> Error()
  }
}
