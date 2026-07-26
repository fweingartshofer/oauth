//// This module implements functions and types for [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
//// It offers types for all the major OAuth 2.0 grant types and functions to create the correct HTTP requests for those grant types.
//// Furthermore, it offers functions to generate redirect URIs for the [Authorization Code Grant Type](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) and the [Implicit Grant Type](https://datatracker.ietf.org/doc/html/rfc6749#section-4.2).
////
//// It also supports [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636), which adds the Proof Key for Code Exchange to the Authorization Code Grant.

import flwr_oauth2/authentication
import flwr_oauth2/common
import flwr_oauth2/response
import flwr_oauth2/token_request

pub type ClientId =
  common.ClientId

pub type Secret =
  common.Secret

pub type Scope =
  common.Scope

pub type TokenRequest =
  token_request.TokenRequest

pub type ClientAuthentication =
  authentication.ClientAuthentication

pub type RequestError =
  token_request.RequestError

pub type ResponseError =
  response.ResponseError

pub type AccessTokenResponse =
  response.AccessTokenResponse

pub type AuthorizationSetter =
  token_request.AuthorizationSetter

pub type UrlEncRequest =
  token_request.UrlEncRequest

pub const to_string_token_response = response.to_string

pub const to_string_token_request = token_request.to_string

pub const to_string_client_authentication = authentication.to_string

pub type RequestModifier =
  token_request.RequestModifier

pub const to_http_request = token_request.to_http_request

pub const to_http_request_with_modifiers = token_request.to_http_request_with_modifiers

pub const to_http_request_with_custom_authentication = token_request.to_http_request_with_custom_authentication

pub const parse_token_response = response.parse_token_response

pub const secret_is_valid = common.secret_is_valid

pub const is_secret_invalid = common.is_secret_invalid

pub const parse_scope = common.parse_scope
