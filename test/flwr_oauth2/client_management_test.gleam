import birdie
import flwr_oauth2/bearer_token
import flwr_oauth2/client_management
import flwr_oauth2/client_registration.{
  ClientInformationResponse, ClientManagement, ClientMetadata, ClientSecretBasic,
}
import flwr_oauth2/common
import flwr_oauth2/response.{AuthorizationServerError} as _
import flwr_oauth2/test_utils
import gleam/dict
import gleam/http/response
import gleam/json
import gleam/option.{None, Some}
import gleam/uri
import gleeunit/should

pub fn client_information_to_http_request_test() {
  // Given
  let assert Ok(reg_uri) = uri.parse("http://example.com")
  let info = ClientManagement(reg_uri, "token")

  // When
  let res = client_management.client_information_to_http_request(info)

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap("client information to http request test")
}

pub fn update_client_information_to_http_request_test() {
  // Given
  let assert Ok(reg_uri) = uri.parse("http://example.com")
  let assert Ok(red_uri) = uri.parse("http://localhost")
  let info = ClientManagement(reg_uri, "token")
  let update =
    ClientInformationResponse(
      client_id: "new-id",
      client_id_issued_at: None,
      client_metadata: ClientMetadata(
        redirect_uris: [red_uri],
        software_statement: None,
        token_endpoint_auth_method: Some(ClientSecretBasic),
        grant_types: [client_registration.AuthorizationCode],
        response_types: [client_registration.Code],
        client_name: Some("New Client"),
        client_name_localized: dict.new(),
        client_uri: Some(red_uri),
        client_uri_localized: dict.new(),
        logo_uri: None,
        logo_uri_localized: dict.new(),
        scope: ["read", "write"],
        contacts: [],
        tos_uri: None,
        tos_uri_localized: dict.new(),
        policy_uri: None,
        policy_uri_localized: dict.new(),
        jwks: client_registration.NoJwks,
        software_id: None,
        software_version: None,
      ),
      client_management: Some(info),
    )

  // When
  let res =
    client_management.update_client_information_to_http_request(info, update)

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap("update client information to http request test")
}

pub fn update_client_information_with_extensions_to_http_request_test() {
  // Given
  let assert Ok(reg_uri) = uri.parse("http://example.com")
  let assert Ok(red_uri) = uri.parse("http://localhost")
  let info = ClientManagement(reg_uri, "token")
  let update =
    ClientInformationResponse(
      client_id: "new-id",
      client_id_issued_at: None,
      client_metadata: ClientMetadata(
        redirect_uris: [red_uri],
        software_statement: None,
        token_endpoint_auth_method: Some(ClientSecretBasic),
        grant_types: [client_registration.AuthorizationCode],
        response_types: [client_registration.Code],
        client_name: Some("New Client"),
        client_name_localized: dict.new(),
        client_uri: Some(red_uri),
        client_uri_localized: dict.new(),
        logo_uri: None,
        logo_uri_localized: dict.new(),
        scope: ["read", "write"],
        contacts: [],
        tos_uri: None,
        tos_uri_localized: dict.new(),
        policy_uri: None,
        policy_uri_localized: dict.new(),
        jwks: client_registration.NoJwks,
        software_id: None,
        software_version: None,
      ),
      client_management: Some(info),
    )

  // When
  let res =
    client_management.update_client_information_with_extensions_to_http_request(
      info,
      update,
      [#("custom_attribute", json.string("asdf"))],
    )

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap(
    "update client information with extensions to http request test",
  )
}

pub fn delete_client_to_http_request_test() {
  // Given
  let assert Ok(reg_uri) = uri.parse("http://example.com")
  let info = ClientManagement(reg_uri, "token")

  // When
  let res = client_management.delete_client_to_http_request(info)

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap("delete client to http request test")
}

pub fn parse_client_information_success_response_test() {
  // Given
  let body =
    "{\"client_id\":\"client-id\",\"client_id_issued_at\":1787590528,\"client_secret\":\"asdf\",\"client_secret_expires_at\":1787590528,\"redirect_uris\":[\"http://localhost:8080/\"],\"token_endpoint_auth_method\":\"client_secret_basic\",\"grant_types\":[\"authorization_code\"],\"response_types\":[\"code\"],\"client_name\":\"gleam-client\",\"scope\":\"read write\"}"

  let resp =
    response.Response(
      status: 200,
      headers: [#("content-type", "application/json; charset: UTF-8")],
      body:,
    )

  // When
  let res = client_management.parse_client_information_response(resp)

  // Then
  res
  |> should.be_ok()
  |> client_registration.client_information_response_to_json()
  |> json.to_string()
  |> birdie.snap("parse client information success response test")
}

pub fn parse_client_information_bad_request_response_test() {
  // Given
  let body = "{\"error\":\"invalid_request\"}"

  let resp =
    response.Response(
      status: 400,
      headers: [#("content-type", "application/json; charset: UTF-8")],
      body:,
    )

  // When
  let res = client_management.parse_client_information_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    client_management.AuthorizationError(AuthorizationServerError(
      400,
      error: "invalid_request",
      error_description: None,
      error_uri: None,
    )),
  )
}

pub fn parse_client_information_unauthorized_response_test() {
  // Given
  let resp =
    response.Response(status: 401, headers: [], body: "")
    |> response.set_header(
      "WWW-Authenticate",
      "Bearer realm=\"dev\",
      scope=\"read write\",
      error=\"invalid_request\"",
    )

  // When
  let res = client_management.parse_client_information_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    client_management.Unauthorized([
      bearer_token.BearerErrorResponse(
        realm: Some("dev"),
        scope: ["read", "write"],
        error: Some("invalid_request"),
        error_description: None,
        error_uri: None,
      ),
    ]),
  )
}

pub fn parse_client_information_forbidden_response_test() {
  // Given
  let resp = response.Response(status: 403, headers: [], body: "")

  // When
  let res = client_management.parse_client_information_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(client_management.Forbidden)
}

pub fn parse_client_information_not_supported_response_test() {
  // Given
  let resp = response.Response(status: 405, headers: [], body: "")

  // When
  let res = client_management.parse_client_information_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(client_management.NotSupported)
}

pub fn parse_client_information_unsupported_content_response_test() {
  // Given
  let resp =
    response.Response(
      status: 200,
      headers: [#("content-type", "application/xml")],
      body: "",
    )

  // When
  let res = client_management.parse_client_information_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    client_management.ParseError(common.UnsupportedContent("application/xml")),
  )
}

pub fn parse_client_information_invalid_status_response_test() {
  // Given
  let resp = response.Response(status: 500, headers: [], body: "")

  // When
  let res = client_management.parse_client_information_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(client_management.InvalidStatus(500))
}

pub fn parse_client_deletion_success_response_test() {
  // Given
  let resp = response.Response(status: 204, headers: [], body: "")

  // When
  let res = client_management.parse_client_deletion_response(resp)

  // Then
  res
  |> should.be_ok()
  |> should.equal(Nil)
}

pub fn parse_client_deletion_error_response_test() {
  // Given
  let resp =
    response.Response(
      status: 400,
      headers: [],
      body: "{\"error\":\"invalid_client\"}",
    )

  // When
  let res = client_management.parse_client_deletion_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    client_management.AuthorizationError(AuthorizationServerError(
      status: 400,
      error: "invalid_client",
      error_description: option.None,
      error_uri: option.None,
    )),
  )
}

pub fn parse_client_deletion_unauthorized_error_response_test() {
  // Given
  let resp =
    response.Response(status: 401, headers: [], body: "")
    |> response.set_header(
      "WWW-Authenticate",
      "Bearer realm=\"dev\",
      scope=\"read write\",
      error=\"invalid_request\"",
    )

  // When
  let res = client_management.parse_client_deletion_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    client_management.Unauthorized([
      bearer_token.BearerErrorResponse(
        realm: Some("dev"),
        scope: ["read", "write"],
        error: Some("invalid_request"),
        error_description: None,
        error_uri: None,
      ),
    ]),
  )
}

pub fn parse_client_deletion_forbidden_error_response_test() {
  // Given
  let resp = response.Response(status: 403, headers: [], body: "")

  // When
  let res = client_management.parse_client_deletion_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(client_management.Forbidden)
}

pub fn parse_client_deletion_not_supported_error_response_test() {
  // Given
  let resp = response.Response(status: 405, headers: [], body: "")

  // When
  let res = client_management.parse_client_deletion_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(client_management.NotSupported)
}

pub fn parse_client_deletion_unsupported_content_error_response_test() {
  // Given
  let resp =
    response.Response(
      status: 400,
      headers: [#("content-type", "application/xml")],
      body: "",
    )

  // When
  let res = client_management.parse_client_deletion_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(
    client_management.ParseError(common.UnsupportedContent("application/xml")),
  )
}

pub fn parse_client_deletion_invalid_error_response_test() {
  // Given
  let resp = response.Response(status: 500, headers: [], body: "")

  // When
  let res = client_management.parse_client_deletion_response(resp)

  // Then
  res
  |> should.be_error()
  |> should.equal(client_management.InvalidStatus(500))
}
