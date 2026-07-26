import flwr_oauth2/common
import flwr_oauth2/helpers
import gleam/dynamic/decode
import gleam/http/response
import gleam/int
import gleam/json
import gleam/option
import gleam/result
import gleam/string

/// This type is returned by this module for a parsed access token response.
pub type AccessTokenResponse {
  /// If the access token request was successful a `AccessTokenResponse` is returned.
  /// it contains the access token, its type, the time when it will expire, a refresh token if present, and the final scope.
  AccessTokenResponse(
    access_token: String,
    token_type: String,
    expires_in: option.Option(Int),
    refresh_token: option.Option(String),
    scope: common.Scope,
  )
}

/// Errors returned by this module when parsing responses, such as token responses from the OAuth 2.0 server.
pub type ResponseError {
  /// If the response contains errors a `ErrorResponse` will be returned.
  /// It contains the HTTP status, the error code string, optionally an error description and an error URI.
  ErrorResponse(
    status: Int,
    error: String,
    error_description: option.Option(String),
    error_uri: option.Option(String),
  )
  /// If the response does not contain valid JSON or does not conform to the error response format defined by [RFC6749 Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) this error will be returned.
  ParseError(error: json.DecodeError)
}

/// Parses a token response and returns the access and refresh token if valid response, otherwise the error response.
pub fn parse_token_response(
  response: response.Response(String),
) -> Result(AccessTokenResponse, ResponseError) {
  case response.status {
    200 -> parse_token_success_response(response)
    _ -> parse_error_response(response) |> Error()
  }
}

fn parse_token_success_response(
  response: response.Response(String),
) -> Result(AccessTokenResponse, ResponseError) {
  let token_decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use expires_in <- decode.optional_field(
      "expires_in",
      option.None,
      decode.optional(decode.int),
    )
    use refresh_token <- decode.optional_field(
      "refresh_token",
      option.None,
      decode.optional(decode.string),
    )
    use scope <- decode.optional_field(
      "scope",
      option.None,
      decode.optional(decode.string),
    )
    let scope =
      scope
      |> option.map(common.parse_scope)
      |> option.unwrap([])
    decode.success(AccessTokenResponse(
      access_token: access_token,
      token_type: token_type,
      expires_in: expires_in,
      refresh_token: refresh_token,
      scope: scope,
    ))
  }
  json.parse(from: response.body, using: token_decoder)
  |> result.map_error(ParseError)
}

/// Parses an OAuth 2.0 error response defined in [RFC6749 Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
pub fn parse_error_response(
  response: response.Response(String),
) -> ResponseError {
  let error_decoder = {
    use error <- decode.field("error", decode.string)
    use error_description <- decode.optional_field(
      "error_description",
      option.None,
      decode.optional(decode.string),
    )
    use error_uri <- decode.optional_field(
      "error_uri",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(ErrorResponse(
      status: response.status,
      error: error,
      error_description: error_description,
      error_uri: error_uri,
    ))
  }
  json.parse(from: response.body, using: error_decoder)
  |> result.map_error(ParseError)
  |> helpers.unwrap_both()
}

/// Creates a String representation of a token request
pub fn to_string(resp: AccessTokenResponse) {
  "AccessTokenResponse(
    access_token: " <> resp.access_token <> ",
    token_type: " <> resp.token_type <> ",
    expires_in: " <> option.unwrap(
    option.map(resp.expires_in, int.to_string),
    "None",
  ) <> "),
    refresh_token: " <> option.unwrap(resp.refresh_token, "None") <> ",
    scope: [" <> string.join(resp.scope, ", ") <> "],
  )"
}
