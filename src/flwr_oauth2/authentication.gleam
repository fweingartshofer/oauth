import flwr_oauth2/common
import flwr_oauth2/http_headers
import gleam/bool
import gleam/http/request.{type Request}
import gleam/list
import gleam/result

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

/// Used to authenticate a client for an HTTP Request to the authorization server.
/// For example, used for token introspection.
/// Returns Error(Nil) if the secret has expired.
pub fn authenticate_http_request(
  request req: Request(List(#(String, String))),
  authentication auth: ClientAuthentication,
) -> Result(Request(List(#(String, String))), Nil) {
  let setter = auth |> authentication_setter()
  setter(req)
}

/// Utility method to authenticate a request with just the ClientSecretBasic authentication mechanism.
/// This is useful for token introspection calls or other requests that need to have a body available while still containing authentication for the client.
/// Basic authentication is singled out, since it is the only authentication mechanism to not require a body for OAuth Authentication Requests.
/// If either the secret is expired or the authentication method is not supported returns Error(Nil).
pub fn basic_authenticate_http_request(
  request req: Request(a),
  authentication auth: ClientAuthentication,
) {
  case auth {
    ClientSecretBasic(client_id:, client_secret:) ->
      compose(
        guard_secret(client_secret),
        set_basic_header(client_id.value, client_secret.value),
      )(req)
    _ -> Error(Nil)
  }
}

/// Encodes the ClientAuthentication that is to be sent to the OAuth 2.0 Server.
/// For Basic Authentication it will always encode it with base64.
fn authentication_setter(
  auth: ClientAuthentication,
) -> fn(Request(List(#(String, String)))) ->
  Result(Request(List(#(String, String))), Nil) {
  case auth {
    ClientSecretPost(client_id, client_secret) ->
      compose(
        guard_secret(client_secret),
        add_body([
          #("client_id", client_id.value),
          #("client_secret", client_secret.value),
        ]),
      )
    PublicAuthentication(client_id) ->
      add_body([
        #("client_id", client_id.value),
      ])
    ClientAssertion(client_id, client_assertion, client_assertion_type) ->
      add_body([
        #("client_id", client_id.value),
        #("client_assertion_type", client_assertion_type),
        #("client_assertion", client_assertion),
      ])
    ClientSecretBasic(client_id, client_secret) ->
      compose(
        guard_secret(client_secret),
        set_basic_header(client_id.value, client_secret.value),
      )
  }
}

fn compose(
  first: fn(Request(a)) -> Result(b, Nil),
  second: fn(b) -> Result(Request(a), Nil),
) -> fn(Request(a)) -> Result(Request(a), Nil) {
  fn(req) {
    req
    |> first
    |> result.try(second)
  }
}

fn guard_secret(
  secret: common.Secret,
) -> fn(Request(a)) -> Result(Request(a), Nil) {
  fn(req) {
    use <- bool.guard(
      when: common.is_secret_invalid(secret),
      return: Error(Nil),
    )
    Ok(req)
  }
}

fn add_body(
  fields: List(#(String, String)),
) -> fn(Request(List(#(String, String)))) ->
  Result(Request(List(#(String, String))), a) {
  fn(req: Request(List(#(String, String)))) {
    req.body
    |> list.append(fields, _)
    |> request.set_body(req, _)
    |> Ok
  }
}

fn set_basic_header(
  client_id: String,
  client_secret: String,
) -> fn(Request(a)) -> Result(Request(a), b) {
  fn(req) {
    req
    |> http_headers.set_basic(client_id, client_secret)
    |> Ok
  }
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
