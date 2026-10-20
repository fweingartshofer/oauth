import birdie
import flwr_oauth2/authorization_grant.{Plain, S256}
import flwr_oauth2/authorization_server_metadata.{
  AuthorizationServerMetadata, FormPost, Fragment, Query,
}
import flwr_oauth2/client_registration.{
  AuthorizationCode, ClientCredentials, ClientSecretBasic, Code,
  OtherResponseType, OtherTokenEndpointAuthMethod, RefreshToken, Token,
}
import flwr_oauth2/common
import flwr_oauth2/jwk
import flwr_oauth2/test_utils
import gleam/http/response
import gleam/option.{Some}
import gleam/uri
import gleeunit/should

pub fn to_http_request_test() {
  // Given
  let assert Ok(uri) =
    uri.parse("https://example.com/.well-known/oauth-authorization-server")

  // When
  let res = authorization_server_metadata.to_http_request(uri)

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap("Authorization Server Metadata To Http Request Test")
}

pub fn parse_http_request_with_invalid_content_type_test() {
  // Given
  let resp =
    response.new(200) |> response.set_header("content-type", "application/xml")

  // When
  let res = authorization_server_metadata.parse_http_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    authorization_server_metadata.ParseError(common.UnsupportedContent(
      "application/xml",
    )),
  )
}

pub fn parse_http_request_with_invalid_status_test() {
  // Given
  let resp =
    response.new(400) |> response.set_header("content-type", "application/json")

  // When
  let res = authorization_server_metadata.parse_http_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(authorization_server_metadata.InvalidStatus(400))
}

pub fn parse_http_request_without_content_type_test() {
  // Given
  let resp =
    response.new(200)
    |> response.set_body(metadata_json())

  // When
  let res = authorization_server_metadata.parse_http_response(resp)

  // Then
  res
  |> should.be_ok()
  |> should.equal(metadata())
}

pub fn parse_http_request_test() {
  // Given
  let resp =
    response.new(200)
    |> response.set_body(metadata_json())
    |> response.set_header("content-type", "application/json")

  // When
  let res = authorization_server_metadata.parse_http_response(resp)

  // Then
  res
  |> should.be_ok()
  |> should.equal(metadata())
}

fn parse_uri(value: String) -> uri.Uri {
  let assert Ok(parsed) = uri.parse(value)
  parsed
}

fn metadata() {
  AuthorizationServerMetadata(
    issuer: parse_uri("https://as.example.com"),
    authorization_endpoint: Some(parse_uri("https://as.example.com/authorize")),
    token_endpoint: Some(parse_uri("https://as.example.com/token")),
    jwks_uri: Some(parse_uri("https://as.example.com/.well-known/jwks.json")),
    registration_endpoint: Some(parse_uri("https://as.example.com/register")),
    scopes_supported: Some(["read", "write"]),
    response_types_supported: [
      Code,
      Token,
      OtherResponseType("code token"),
    ],
    response_modes_supported: [Query, Fragment, FormPost],
    grant_types_supported: [
      AuthorizationCode,
      ClientCredentials,
      RefreshToken,
    ],
    token_endpoint_auth_methods_supported: [
      ClientSecretBasic,
      OtherTokenEndpointAuthMethod("private_key_jwt"),
    ],
    token_endpoint_auth_signing_alg_values_supported: [jwk.RS256] |> Some,
    service_documentation: Some(parse_uri("https://as.example.com/docs")),
    ui_locales_supported: ["en-US", "fr-FR"] |> Some,
    op_policy_uri: Some(parse_uri("https://as.example.com/privacy")),
    op_tos_uri: Some(parse_uri("https://as.example.com/terms")),
    revocation_endpoint: Some(parse_uri("https://as.example.com/revoke")),
    revocation_endpoint_auth_methods_supported: [
      OtherTokenEndpointAuthMethod("private_key_jwt"),
    ],
    revocation_endpoint_auth_signing_alg_values_supported: [jwk.RS256] |> Some,
    introspection_endpoint: Some(parse_uri("https://as.example.com/introspect")),
    introspection_endpoint_auth_methods_supported: Some([
      OtherTokenEndpointAuthMethod("private_key_jwt"),
    ]),
    introspection_endpoint_auth_signing_alg_values_supported: [jwk.RS256]
      |> Some,
    code_challenge_methods_supported: Some([
      S256,
      Plain,
    ]),
    signed_metadata: Some(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
    ),
  )
}

fn metadata_json() {
  "{\"issuer\":\"https://as.example.com\",\"authorization_endpoint\":\"https://as.example.com/authorize\",\"token_endpoint\":\"https://as.example.com/token\",\"jwks_uri\":\"https://as.example.com/.well-known/jwks.json\",\"registration_endpoint\":\"https://as.example.com/register\",\"scopes_supported\":[\"read\",\"write\"],\"response_types_supported\":[\"code\",\"token\",\"code token\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"private_key_jwt\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],\"service_documentation\":\"https://as.example.com/docs\",\"ui_locales_supported\":[\"en-US\",\"fr-FR\"],\"op_policy_uri\":\"https://as.example.com/privacy\",\"op_tos_uri\":\"https://as.example.com/terms\",\"revocation_endpoint\":\"https://as.example.com/revoke\",\"revocation_endpoint_auth_methods_supported\":[\"private_key_jwt\"],\"revocation_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],\"introspection_endpoint\":\"https://as.example.com/introspect\",\"introspection_endpoint_auth_methods_supported\":[\"private_key_jwt\"],\"introspection_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],\"code_challenge_methods_supported\":[\"S256\",\"plain\"],\"signed_metadata\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30\"}"
}
