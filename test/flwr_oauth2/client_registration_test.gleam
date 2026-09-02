import birdie
import flwr_oauth2/client_registration.{
  AuthorizationCode, ByUri, ClientMetadata, ClientSecretBasic, Code, NoJwks,
}
import flwr_oauth2/common
import flwr_oauth2/test_utils
import gleam/dict
import gleam/http/response
import gleam/json
import gleam/option.{None, Some}
import gleam/time/timestamp
import gleam/uri
import gleeunit/should

pub fn to_http_request_correctly_serializes_data_test() {
  // Given
  let assert Ok(client_creation_endpoint) = uri.parse("https://localhost")
  let assert Ok(redirect_uri) = uri.parse("http://localhost:8080")
  let access_token = Some("asdf")
  let assert Ok(at_client_uri) = uri.parse("http://localhost:8080/de-AT")
  let assert Ok(logo_uri) = uri.parse("http://localhost:8080/logo.svg")
  let assert Ok(at_logo_uri) = uri.parse("http://localhost:8080/de-AT/logo.svg")
  let assert Ok(tos_uri) = uri.parse("http://localhost:8080/tos")
  let assert Ok(at_tos_uri) = uri.parse("http://localhost:8080/de-AT/tos")
  let assert Ok(policy_uri) = uri.parse("http://localhost:8080/policy")
  let assert Ok(at_policy_uri) = uri.parse("http://localhost:8080/de-AT/policy")
  let assert Ok(jwks_uri) = uri.parse("http://localhost:8080/uri")
  let client_metadata =
    ClientMetadata(
      redirect_uris: [redirect_uri],
      software_statement: Some(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
      ),
      token_endpoint_auth_method: Some(ClientSecretBasic),
      grant_types: [AuthorizationCode],
      response_types: [Code],
      client_name: Some("gleam-client"),
      client_name_localized: dict.from_list([#("de-AT", "Gleam Klient")]),
      client_uri: Some(redirect_uri),
      client_uri_localized: dict.from_list([#("de-AT", at_client_uri)]),
      logo_uri: Some(logo_uri),
      logo_uri_localized: dict.from_list([#("de-AT", at_logo_uri)]),
      scope: ["read", "write"],
      contacts: ["info@example.com"],
      tos_uri: Some(tos_uri),
      tos_uri_localized: dict.from_list([#("de-AT", at_tos_uri)]),
      policy_uri: Some(policy_uri),
      policy_uri_localized: dict.from_list([#("de-AT", at_policy_uri)]),
      jwks: ByUri(jwks_uri),
      software_id: Some("unique-id"),
      software_version: Some("v1.0.1"),
    )
  let client_registration_request =
    client_registration.ClientRegistrationRequest(
      client_creation_endpoint:,
      access_token:,
      client_metadata:,
    )

  // When
  let res = client_registration.to_http_request(client_registration_request)

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap(
    "Client Registration Request is correctly serialized to HTTP Request",
  )
}

pub fn to_http_request_without_metadata_correctly_serializes_data_test() {
  // Given
  let assert Ok(client_creation_endpoint) = uri.parse("https://localhost")
  let client_metadata =
    ClientMetadata(
      redirect_uris: [],
      software_statement: None,
      token_endpoint_auth_method: None,
      grant_types: [],
      response_types: [],
      client_name: None,
      client_name_localized: dict.new(),
      client_uri: None,
      client_uri_localized: dict.new(),
      logo_uri: None,
      logo_uri_localized: dict.new(),
      scope: [],
      contacts: [],
      tos_uri: None,
      tos_uri_localized: dict.new(),
      policy_uri: None,
      policy_uri_localized: dict.new(),
      jwks: NoJwks,
      software_id: None,
      software_version: None,
    )
  let client_registration_request =
    client_registration.ClientRegistrationRequest(
      client_creation_endpoint:,
      access_token: None,
      client_metadata:,
    )

  // When
  let res = client_registration.to_http_request(client_registration_request)

  // Then
  res
  |> should.be_ok()
  |> test_utils.request_to_string()
  |> birdie.snap(
    "Client Registration Request with empty metadata is correctly serialized to HTTP Request",
  )
}

pub fn parse_client_registration_response_test() {
  // Given
  let body =
    "{\"client_id\":\"client-id\",\"client_id_issued_at\":1787590528,\"client_secret\":\"asdf\",\"client_secret_expires_at\":1787590528,\"redirect_uris\":[\"http://localhost:8080/\"],\"software_statement\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"grant_types\":[\"authorization_code\"],\"response_types\":[\"code\"],\"client_name\":\"gleam-client\",\"client_name#de-AT\":\"Gleam Klient\",\"client_uri\":\"http://localhost:8080/\",\"client_uri#de-AT\":\"http://localhost:8080/de-AT\",\"logo_uri\":\"http://localhost:8080/logo.svg\",\"logo_uri#de-AT\":\"http://localhost:8080/de-AT/logo.svg\",\"scope\":\"read write\",\"contacts\":[\"info@example.com\"],\"tos_uri\":\"http://localhost:8080/tos\",\"tos_uri#de-AT\":\"http://localhost:8080/de-AT/tos\",\"policy_uri\":\"http://localhost:8080/policy\",\"policy_uri#de-AT\":\"http://localhost:8080/de-AT/policy\",\"jwks_uri\":\"http://localhost:8080/uri\",\"software_id\":\"unique-id\",\"software_version\":\"v1.0.1\"}"
  let resp =
    response.Response(
      status: 201,
      headers: [#("content-type", "application/json; charset: UTF-8")],
      body:,
    )

  // When
  let res = client_registration.parse_client_registration_response(resp)

  // Then
  let resp = res |> should.be_ok()
  case resp {
    client_registration.ConfidentialClientInformationResponse(
      client_id:,
      client_id_issued_at:,
      client_metadata:,
      client_secret:,
    ) -> {
      client_id |> should.equal("client-id")
      client_id_issued_at
      |> should.equal(Some(timestamp.from_unix_seconds(1_787_590_528)))
      client_secret
      |> should.equal(common.SecretWithExpiration(
        "asdf",
        timestamp.from_unix_seconds(1_787_590_528),
      ))
      client_metadata
      |> client_registration.client_metadata_to_json()
      |> json.to_string()
      |> birdie.snap("Parse client registration response test")
    }

    _ -> should.fail()
  }
}

pub fn parse_client_registration_response_without_expiring_secret_test() {
  // Given
  let body =
    "{\"client_id\":\"client-id\",\"client_id_issued_at\":1787590528,\"client_secret\":\"asdf\",\"redirect_uris\":[\"http://localhost:8080/\"],\"software_statement\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"grant_types\":[\"authorization_code\"],\"response_types\":[\"code\"],\"client_name\":\"gleam-client\",\"client_name#de-AT\":\"Gleam Klient\",\"client_uri\":\"http://localhost:8080/\",\"client_uri#de-AT\":\"http://localhost:8080/de-AT\",\"logo_uri\":\"http://localhost:8080/logo.svg\",\"logo_uri#de-AT\":\"http://localhost:8080/de-AT/logo.svg\",\"scope\":\"read write\",\"contacts\":[\"info@example.com\"],\"tos_uri\":\"http://localhost:8080/tos\",\"tos_uri#de-AT\":\"http://localhost:8080/de-AT/tos\",\"policy_uri\":\"http://localhost:8080/policy\",\"policy_uri#de-AT\":\"http://localhost:8080/de-AT/policy\",\"jwks_uri\":\"http://localhost:8080/uri\",\"software_id\":\"unique-id\",\"software_version\":\"v1.0.1\"}"
  let resp =
    response.Response(
      status: 201,
      headers: [#("content-type", "application/json; charset: UTF-8")],
      body:,
    )

  // When
  let res = client_registration.parse_client_registration_response(resp)

  // Then
  let resp = res |> should.be_ok()
  case resp {
    client_registration.ConfidentialClientInformationResponse(
      client_id:,
      client_id_issued_at:,
      client_metadata:,
      client_secret:,
    ) -> {
      client_id |> should.equal("client-id")
      client_id_issued_at
      |> should.equal(Some(timestamp.from_unix_seconds(1_787_590_528)))
      client_secret
      |> should.equal(common.Secret("asdf"))
      client_metadata
      |> client_registration.client_metadata_to_json()
      |> json.to_string()
      |> birdie.snap(
        "Parse client registration response without expiring secret test",
      )
    }

    _ -> should.fail()
  }
}
