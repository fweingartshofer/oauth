import flwr_oauth2/common

/// The type of client authentication that should be used with the OAuth 2.0 Server.
/// An OAuth 2.0 Server can support multiple kinds of client authentication.
/// When the incorrect kind is used, the OAuth 2.0 Server will respond with an error.
/// For the error information see [RFC6749 Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-7.2).
pub type ClientAuthentication {
  /// Use this type if the OAuth 2.0 Server accepts HTTP Basic authentication, which sets the `Authorization` header in the HTTP request.
  /// For example:
  /// ```
  /// Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
  /// ```
  ClientSecretBasic(client_id: common.ClientId, client_secret: common.Secret)
  /// Use this type if the OAuth 2.0 Server accepts the credentials via a POST request.
  /// In that case the credentials are sent URL encoded.
  /// For example:
  /// ```
  /// client_id=asdf&client_secret=hjkl
  /// ```
  ClientSecretPost(client_id: common.ClientId, client_secret: common.Secret)
  /// Use this type if the client is public and there is no client secret to be included.
  PublicAuthentication(client_id: common.ClientId)
  /// Use this type if the OAuth 2.0 Server accepts a JWT assertion for client authentication.
  /// See [RFC7523 Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2)
  ClientAssertion(
    client_id: common.ClientId,
    client_assertion: String,
    client_assertion_type: String,
  )
}

pub fn to_string(client_auth: ClientAuthentication) -> String {
  case client_auth {
    ClientSecretBasic(client_id:, ..) ->
      "ClientSecretBasic("
      <> "client_id="
      <> client_id.value
      <> ", "
      <> "client_secret=***"
      <> ")"

    ClientSecretPost(client_id:, ..) ->
      "ClientSecretPost("
      <> "client_id="
      <> client_id.value
      <> ", "
      <> "client_secret=***"
      <> ")"

    PublicAuthentication(client_id:) ->
      "PublicAuthentication(" <> "client_id=" <> client_id.value <> ")"
    ClientAssertion(client_id:, client_assertion_type:, ..) ->
      "ClientSecretJwt("
      <> "client_id="
      <> client_id.value
      <> ", "
      <> "client_assertion=***, "
      <> "client_assertion_type="
      <> client_assertion_type
      <> ")"
  }
}
