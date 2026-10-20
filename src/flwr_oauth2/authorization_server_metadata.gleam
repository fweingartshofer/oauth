//// This module implements [RFC8414 OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414).

import flwr_oauth2/authorization_grant.{type CodeChallengeMethod}
import flwr_oauth2/client_registration.{
  type GrantType, type ResponseType, type TokenEndpointAuthMethod,
  AuthorizationCode, Implicit,
}
import flwr_oauth2/common.{type Scope}
import flwr_oauth2/helpers
import flwr_oauth2/jwk.{type Algorithm}
import flwr_oauth2/token_request
import gleam/dynamic/decode.{type Decoder}
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/option.{type Option, None}
import gleam/result
import gleam/uri.{type Uri}

/// Represents the document returned by the RFC8414 Authorization Server Metadata Endpoint.
pub type AuthorizationServerMetadata {
  AuthorizationServerMetadata(
    issuer: Uri,
    authorization_endpoint: Option(Uri),
    token_endpoint: Option(Uri),
    jwks_uri: Option(Uri),
    registration_endpoint: Option(Uri),
    scopes_supported: Option(Scope),
    response_types_supported: List(ResponseType),
    response_modes_supported: List(ResponseMode),
    grant_types_supported: List(GrantType),
    token_endpoint_auth_methods_supported: List(TokenEndpointAuthMethod),
    token_endpoint_auth_signing_alg_values_supported: Option(List(Algorithm)),
    service_documentation: Option(Uri),
    ui_locales_supported: Option(List(String)),
    op_policy_uri: Option(Uri),
    op_tos_uri: Option(Uri),
    revocation_endpoint: Option(Uri),
    revocation_endpoint_auth_methods_supported: List(TokenEndpointAuthMethod),
    revocation_endpoint_auth_signing_alg_values_supported: Option(
      List(Algorithm),
    ),
    introspection_endpoint: Option(Uri),
    introspection_endpoint_auth_methods_supported: Option(
      List(TokenEndpointAuthMethod),
    ),
    introspection_endpoint_auth_signing_alg_values_supported: Option(
      List(Algorithm),
    ),
    code_challenge_methods_supported: Option(List(CodeChallengeMethod)),
    signed_metadata: Option(String),
  )
}

pub type ResponseMode {
  Query
  Fragment
  FormPost
  OtherResponseMode(value: String)
}

/// Utility method to create a request from the .well-known endpoint for the authorization server metadata document.
/// This method assumes that the endpoint provided is an already constructed endpoint.
pub fn to_http_request(
  endpoint: Uri,
) -> Result(request.Request(String), token_request.RequestError) {
  let req =
    request.from_uri(endpoint)
    |> result.replace_error(token_request.InvalidUri)
  use req <- result.map(req)
  req |> request.set_header("accept", "application/json")
}

pub type AuthorizationServerMetadataResponseError {
  ParseError(common.ParseError)
  InvalidStatus(status: Int)
}

/// Parses the body of the response of the metadata endpoint.
/// Only parses fields declared by RFC8414, others are ignored.
/// If they are required create a decoder for the missing fields, such as the ones required for OIDC discovery mechanism.
/// According to RFC8414, the issuer field has to match exactly the request URI, since Gleam responses do not contain the original request URI this cannot be validated by this method.
/// Furthermore, this method does not validate that the issuer URI does not contain any fragments or query parts.
pub fn parse_http_response(
  response resp: response.Response(String),
) -> Result(
  AuthorizationServerMetadata,
  AuthorizationServerMetadataResponseError,
) {
  let is_json = resp |> helpers.verify_content_type("application/json")
  case resp.status, is_json {
    200, Ok(Nil) | 200, Error(helpers.MissingContentType) ->
      resp.body
      |> json.parse(authorization_server_metadata_decoder())
      |> result.map_error(common.ParseError)
      |> result.map_error(ParseError)
    _, Error(helpers.OtherContentType(value)) ->
      value |> common.UnsupportedContent |> ParseError |> Error
    status, _ -> status |> InvalidStatus |> Error
  }
}

fn enum_decoder(func: fn(String) -> Decoder(a)) -> Decoder(a) {
  decode.then(decode.string, func)
}

fn enum_list_decoder(func: fn(String) -> Decoder(a)) {
  enum_decoder(func) |> decode.list()
}

fn authorization_server_metadata_decoder() -> Decoder(
  AuthorizationServerMetadata,
) {
  use issuer <- decode.field("issuer", common.uri_decoder())
  use authorization_endpoint <- decode.optional_field(
    "authorization_endpoint",
    None,
    decode.optional(common.uri_decoder()),
  )
  use token_endpoint <- decode.optional_field(
    "token_endpoint",
    None,
    decode.optional(common.uri_decoder()),
  )
  use jwks_uri <- decode.optional_field(
    "jwks_uri",
    None,
    decode.optional(common.uri_decoder()),
  )
  use registration_endpoint <- decode.optional_field(
    "registration_endpoint",
    None,
    decode.optional(common.uri_decoder()),
  )
  use scopes_supported <- decode.optional_field(
    "scopes_supported",
    None,
    decode.optional(decode.list(decode.string)),
  )
  use response_types_supported <- decode.field(
    "response_types_supported",
    decode.list(decode.then(
      decode.string,
      client_registration.response_type_decoder,
    )),
  )
  use response_modes_supported <- decode.optional_field(
    "response_modes_supported",
    None,
    enum_list_decoder(response_mode_decoder) |> decode.optional,
  )
  let response_modes_supported =
    response_modes_supported |> option.unwrap([Query, Fragment])
  use grant_types_supported <- decode.optional_field(
    "grant_types_supported",
    None,
    enum_list_decoder(client_registration.grant_type_decoder) |> decode.optional,
  )
  let grant_types_supported =
    grant_types_supported |> option.unwrap([AuthorizationCode, Implicit])
  use token_endpoint_auth_methods_supported <- decode.optional_field(
    "token_endpoint_auth_methods_supported",
    None,
    enum_list_decoder(client_registration.token_endpoint_auth_method_decoder)
      |> decode.optional,
  )
  let token_endpoint_auth_methods_supported =
    token_endpoint_auth_methods_supported
    |> option.unwrap([client_registration.ClientSecretBasic])
  use token_endpoint_auth_signing_alg_values_supported <- decode.optional_field(
    "token_endpoint_auth_signing_alg_values_supported",
    None,
    enum_list_decoder(jwk.algorithm_decoder)
      |> decode.optional(),
  )
  use service_documentation <- decode.optional_field(
    "service_documentation",
    None,
    decode.optional(common.uri_decoder()),
  )
  use ui_locales_supported <- decode.optional_field(
    "ui_locales_supported",
    None,
    decode.list(decode.string) |> decode.optional(),
  )
  use op_policy_uri <- decode.optional_field(
    "op_policy_uri",
    None,
    decode.optional(common.uri_decoder()),
  )
  use op_tos_uri <- decode.optional_field(
    "op_tos_uri",
    None,
    decode.optional(common.uri_decoder()),
  )
  use revocation_endpoint <- decode.optional_field(
    "revocation_endpoint",
    None,
    decode.optional(common.uri_decoder()),
  )
  use revocation_endpoint_auth_methods_supported <- decode.optional_field(
    "revocation_endpoint_auth_methods_supported",
    None,
    enum_list_decoder(client_registration.token_endpoint_auth_method_decoder)
      |> decode.optional(),
  )
  let revocation_endpoint_auth_methods_supported =
    revocation_endpoint_auth_methods_supported
    |> option.unwrap([client_registration.ClientSecretBasic])
  use revocation_endpoint_auth_signing_alg_values_supported <- decode.optional_field(
    "revocation_endpoint_auth_signing_alg_values_supported",
    None,
    enum_list_decoder(jwk.algorithm_decoder)
      |> decode.optional(),
  )
  use introspection_endpoint <- decode.optional_field(
    "introspection_endpoint",
    None,
    decode.optional(common.uri_decoder()),
  )
  use introspection_endpoint_auth_methods_supported <- decode.optional_field(
    "introspection_endpoint_auth_methods_supported",
    None,
    enum_list_decoder(client_registration.token_endpoint_auth_method_decoder)
      |> decode.optional(),
  )
  use introspection_endpoint_auth_signing_alg_values_supported <- decode.optional_field(
    "introspection_endpoint_auth_signing_alg_values_supported",
    None,
    enum_list_decoder(jwk.algorithm_decoder)
      |> decode.optional(),
  )
  use code_challenge_methods_supported <- decode.optional_field(
    "code_challenge_methods_supported",
    None,
    enum_list_decoder(authorization_grant.code_challange_method_decoder)
      |> decode.optional(),
  )
  use signed_metadata <- decode.optional_field(
    "signed_metadata",
    None,
    decode.optional(decode.string),
  )
  decode.success(AuthorizationServerMetadata(
    issuer:,
    authorization_endpoint:,
    token_endpoint:,
    jwks_uri:,
    registration_endpoint:,
    scopes_supported:,
    response_types_supported:,
    response_modes_supported:,
    grant_types_supported:,
    token_endpoint_auth_methods_supported:,
    token_endpoint_auth_signing_alg_values_supported:,
    service_documentation:,
    ui_locales_supported:,
    op_policy_uri:,
    op_tos_uri:,
    revocation_endpoint:,
    revocation_endpoint_auth_methods_supported:,
    revocation_endpoint_auth_signing_alg_values_supported:,
    introspection_endpoint:,
    introspection_endpoint_auth_methods_supported:,
    introspection_endpoint_auth_signing_alg_values_supported:,
    code_challenge_methods_supported:,
    signed_metadata:,
  ))
}

fn response_mode_decoder(value: String) -> Decoder(ResponseMode) {
  case value {
    "query" -> Query
    "fragment" -> Fragment
    "form_post" -> FormPost
    value -> OtherResponseMode(value:)
  }
  |> decode.success()
}
