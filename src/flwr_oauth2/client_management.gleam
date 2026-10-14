/// This module implements the functionality to read and update clients according to [RFC7592](https://datatracker.ietf.org/doc/html/rfc7592).
import flwr_oauth2/bearer_token
import flwr_oauth2/client_registration.{
  type ClientInformationResponse, type ClientManagement, ClientManagement,
}
import flwr_oauth2/common
import flwr_oauth2/helpers
import flwr_oauth2/response as oauth_response
import flwr_oauth2/token_request
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response
import gleam/json
import gleam/result

pub type ClientManagementErrorResponse {
  /// Error if the bearer token is not valid
  Unauthorized(List(bearer_token.BearerErrorResponse))
  AuthorizationError(oauth_response.AuthorizationServerError)
  /// The client is not allowed to access this resource
  Forbidden
  /// This operation is not supported by the authorization server
  NotSupported
  /// The authorization server responded with an unknown invalid status
  InvalidStatus(status: Int)
  /// The response from the authorization server could not be parsed
  ParseError(common.ParseError)
}

/// Creates a read (GET) request to the client information endpoint using the provided access token.
/// This will just read the client information and not change anything, see [RFC7592 Section 2.1](https://datatracker.ietf.org/doc/html/rfc7592#section-2.1).
/// To parse the response, see [parse_client_information_response](#parse_client_information_response)
/// **IMPORTANT**: The endpoint should be secured with HTTPS for production use cases.
pub fn client_information_to_http_request(
  management_info: ClientManagement,
) -> Result(Request(String), token_request.RequestError) {
  let req = management_info |> provision_http_request()
  use req <- result.map(req)
  req |> request.set_method(http.Get)
}

/// Creates an update (PUT) request to the client information endpoint using the provided access token.
/// This will update the client information, see [RFC7592 Section 2.2](https://datatracker.ietf.org/doc/html/rfc7592#section-2.2).
/// Any custom extensions will be deleted per RFC7592 as null or non-present values are deleted.
/// For custom extensions use [update_client_information_with_extensions_to_http_request][#update_client_information_with_extensions_to_http_request], as this will preserve the custom extensions.
/// To parse the response, see [parse_client_information_response](#parse_client_information_response)
/// **IMPORTANT**: The endpoint should be secured with HTTPS for production use cases.
pub fn update_client_information_to_http_request(
  management_info: ClientManagement,
  client_update: ClientInformationResponse,
) -> Result(Request(String), token_request.RequestError) {
  update_client_information_with_extensions_to_http_request(
    management_info,
    client_update,
    [],
  )
}

/// Creates an update (PUT) request to the client information endpoint using the provided access token.
/// This will update the client information including any custom extensions, see [RFC7592 Section 2.2](https://datatracker.ietf.org/doc/html/rfc7592#section-2.2).
/// Extensions are serialized verbatim. Do not include fields prohibited in RFC 7592 Section 2.2 (registration_access_token, registration_client_uri, client_secret_expires_at, or client_id_issued_at), or keys already supplied by the typed metadata. Duplicate JSON keys may be handled unpredictably by the server.
/// To parse the response, see [parse_client_information_response](#parse_client_information_response).
/// **IMPORTANT**: The endpoint should be secured with HTTPS for production use cases.
pub fn update_client_information_with_extensions_to_http_request(
  management_info: ClientManagement,
  client_update: ClientInformationResponse,
  extensions: List(#(String, json.Json)),
) -> Result(Request(String), token_request.RequestError) {
  let req = management_info |> provision_http_request()
  use req <- result.map(req)
  let body =
    client_registration.client_information_response_with_extensions_to_json(
      client_update,
      extensions,
    )
    |> json.to_string()
  req
  |> request.set_method(http.Put)
  |> request.set_header("Content-Type", "application/json")
  |> request.set_body(body)
}

/// Creates a delete (DELETE) request to the client information endpoint using the provided access token.
/// This will delete the client, see [RFC7592 Section 2.3](https://datatracker.ietf.org/doc/html/rfc7592#section-2.3).
/// To parse the response, see [parse_client_deletion_response](#parse_client_deletion_response).
/// **IMPORTANT**: The endpoint should be secured with HTTPS for production use cases.
pub fn delete_client_to_http_request(
  management_info: ClientManagement,
) -> Result(Request(String), token_request.RequestError) {
  let req = management_info |> provision_http_request()
  use req <- result.map(req)
  req
  |> request.set_method(http.Delete)
}

fn provision_http_request(
  management_info: ClientManagement,
) -> Result(Request(String), token_request.RequestError) {
  let ClientManagement(uri, token) = management_info
  let req =
    request.from_uri(uri) |> result.replace_error(token_request.InvalidUri)
  use req <- result.map(req)
  req
  |> bearer_token.attach_bearer_token_string_to_header(token)
  |> request.set_header("Accept", "application/json")
}

/// Parses the response from the client information endpoint, can be used if the client has been updated or if it was read.
/// See https://datatracker.ietf.org/doc/html/rfc7592#section-2.1 and https://datatracker.ietf.org/doc/html/rfc7592#section-2.2
/// NOTE: If any custom extensions are included in the response, parse them out of the low level response manually.
pub fn parse_client_information_response(
  response resp: response.Response(String),
) -> Result(ClientInformationResponse, ClientManagementErrorResponse) {
  let json_response = resp |> helpers.verify_content_type("application/json")
  case resp.status, json_response {
    200, Ok(_) | 200, Error(helpers.MissingContentType) ->
      json.parse(
        resp.body,
        client_registration.client_information_response_decoder(),
      )
      |> result.map_error(common.ParseError)
      |> result.map_error(ParseError)
    400, Ok(_) | 400, Error(helpers.MissingContentType) ->
      oauth_response.parse_error_response(resp)
      |> result.map(AuthorizationError)
      |> result.map_error(ParseError)
      |> helpers.unwrap_both()
      |> Error
    401, _ ->
      bearer_token.parse_bearer_error_response(resp)
      |> result.unwrap([])
      |> Unauthorized
      |> Error
    403, _ -> Error(Forbidden)
    405, _ -> Error(NotSupported)
    _, Error(helpers.OtherContentType(ct)) ->
      common.UnsupportedContent(ct) |> ParseError |> Error
    _, _ -> InvalidStatus(resp.status) |> Error
  }
}

/// Parses the response from the client information endpoint, can be used if the client has been deleted.
/// See [RFC7592 Section 2.3](https://datatracker.ietf.org/doc/html/rfc7592#section-2.3).
/// Returns Ok(Nil) if the client was deleted successfully, otherwise returns the error.
pub fn parse_client_deletion_response(
  response resp: response.Response(String),
) -> Result(Nil, ClientManagementErrorResponse) {
  let json_response = resp |> helpers.verify_content_type("application/json")
  case resp.status, json_response {
    204, _ -> Ok(Nil)
    400, Ok(_) | 400, Error(helpers.MissingContentType) ->
      oauth_response.parse_error_response(resp)
      |> result.map(AuthorizationError)
      |> result.map_error(ParseError)
      |> helpers.unwrap_both()
      |> Error
    401, _ ->
      bearer_token.parse_bearer_error_response(resp)
      |> result.unwrap([])
      |> Unauthorized
      |> Error
    403, _ -> Error(Forbidden)
    405, _ -> Error(NotSupported)
    _, Error(helpers.OtherContentType(ct)) ->
      common.UnsupportedContent(ct) |> ParseError |> Error
    _, _ -> InvalidStatus(resp.status) |> Error
  }
}
