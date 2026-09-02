/// This module implements the [RFC7591 OAuth 2.0 Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)
import flwr_oauth2/bearer_token
import flwr_oauth2/common.{
  type Scope, json_attach_list_member, json_attach_member, uri_decoder,
  uri_to_json,
}
import flwr_oauth2/jwk.{type JwkSet}
import gleam/bool
import gleam/dict.{type Dict}
import gleam/dynamic
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import gleam/uri.{type Uri}

pub type ClientRegistrationRequest {
  ClientRegistrationRequest(
    client_creation_endpoint: Uri,
    access_token: Option(String),
    client_metadata: ClientMetadata,
  )
}

pub type RequestError {
  InvalidUri(uri: Uri)
}

const application_json = "application/json"

pub fn to_http_request(
  client_registration_request: ClientRegistrationRequest,
) -> Result(request.Request(String), RequestError) {
  let ClientRegistrationRequest(
    client_creation_endpoint:,
    access_token:,
    client_metadata:,
  ) = client_registration_request
  let req =
    request.from_uri(client_creation_endpoint)
    |> result.replace_error(InvalidUri(client_creation_endpoint))
  use req <- result.map(req)
  let body =
    client_metadata_to_json(client_metadata)
    |> json.to_string()
  access_token
  |> option.map(bearer_token.attach_bearer_token_string_to_header(req, _))
  |> option.unwrap(req)
  |> request.set_header("Content-Type", application_json)
  |> request.set_header("Accept", application_json)
  |> request.set_body(body)
  |> request.set_method(http.Post)
}

pub type ClientInformationResponse {
  ClientInformationResponse(
    client_id: String,
    client_id_issued_at: Option(Timestamp),
    client_metadata: ClientMetadata,
  )
  ConfidentialClientInformationResponse(
    client_id: String,
    client_id_issued_at: Option(Timestamp),
    client_metadata: ClientMetadata,
    client_secret: common.Secret,
  )
}

pub fn parse_client_registration_response(
  response resp: response.Response(String),
) -> Result(ClientInformationResponse, ResponseError) {
  let ct =
    response.get_header(resp, "Content-Type") |> result.map(string.lowercase)
  let is_json =
    ct
    |> result.map(drop_after(source: _, after: ";"))
    |> result.map(fn(x) { application_json == x })
  case resp.status, is_json {
    201, Ok(True) -> parse_success_response(resp)
    _, Ok(True) -> parse_error_response(resp)
    _, _ -> Error(UnsupportedContent(option.from_result(ct)))
  }
}

fn drop_after(source source: String, after after: String) -> String {
  case string.split_once(source, after) {
    Ok(#(head, _)) -> head
    _ -> source
  }
}

fn parse_success_response(
  resp: response.Response(String),
) -> Result(ClientInformationResponse, ResponseError) {
  json.parse(resp.body, client_information_response_decoder())
  |> result.map_error(MalformedMessageBody)
}

fn parse_error_response(
  resp: response.Response(String),
) -> Result(ClientInformationResponse, ResponseError) {
  case json.parse(resp.body, error_response_decoder(resp.status)) {
    Ok(err) -> Error(err)
    Error(err) -> Error(MalformedMessageBody(err))
  }
}

fn client_information_response_decoder() -> decode.Decoder(
  ClientInformationResponse,
) {
  let timestamp_decoder = {
    use seconds <- decode.then(decode.int)
    decode.success(timestamp.from_unix_seconds(seconds))
  }
  use client_id <- decode.field("client_id", decode.string)
  use client_id_issued_at <- decode.optional_field(
    "client_id_issued_at",
    option.None,
    decode.optional(timestamp_decoder),
  )
  use client_metadata <- decode.then(client_metadata_decoder())
  use client_secret <- decode.optional_field(
    "client_secret",
    option.None,
    decode.optional(decode.string),
  )
  case client_secret {
    option.None ->
      decode.success(ClientInformationResponse(
        client_id:,
        client_id_issued_at:,
        client_metadata:,
      ))
    option.Some(client_secret) -> {
      use client_secret_expires_at <- decode.field(
        "client_secret_expires_at",
        decode.int,
      )
      let client_secret = case client_secret_expires_at {
        0 -> common.Secret(client_secret)
        exp ->
          common.SecretWithExpiration(
            client_secret,
            timestamp.from_unix_seconds_and_nanoseconds(exp, 0),
          )
      }
      decode.success(ConfidentialClientInformationResponse(
        client_id:,
        client_id_issued_at:,
        client_metadata:,
        client_secret:,
      ))
    }
  }
}

pub type ResponseError {
  MalformedMessageBody(json.DecodeError)
  ErrorResponse(status: Int, error: String, error_description: Option(String))
  UnsupportedContent(content_type: Option(String))
}

fn error_response_decoder(status: Int) -> decode.Decoder(ResponseError) {
  use error <- decode.field("error", decode.string)
  use error_description <- decode.optional_field(
    "error_description",
    option.None,
    decode.optional(decode.string),
  )
  decode.success(ErrorResponse(status:, error:, error_description:))
}

pub type ClientMetadata {
  ClientMetadata(
    redirect_uris: List(Uri),
    software_statement: Option(String),
    token_endpoint_auth_method: Option(TokenEndpointAuthMethod),
    grant_types: List(GrantType),
    response_types: List(ResponseType),
    client_name: Option(String),
    /// The localized variant of the client name.
    /// The key should only be the local for the localized name, for example "ja-Jpan-JP".
    /// Setting the key to "client_name#ja-Jpan-JP" would be incorrect.
    /// The same goes for all other localized variants
    client_name_localized: Dict(String, String),
    client_uri: Option(Uri),
    client_uri_localized: Dict(String, Uri),
    logo_uri: Option(Uri),
    logo_uri_localized: Dict(String, Uri),
    scope: Scope,
    contacts: List(String),
    tos_uri: Option(Uri),
    tos_uri_localized: Dict(String, Uri),
    policy_uri: Option(Uri),
    policy_uri_localized: Dict(String, Uri),
    jwks: JwksLocation,
    software_id: Option(String),
    software_version: Option(String),
  )
}

pub fn client_metadata_decoder() -> decode.Decoder(ClientMetadata) {
  let uri_field_decoder = decode.then(decode.string, uri_decoder)
  use fields <- decode.then(decode.dict(decode.string, decode.dynamic))
  use redirect_uris <- decode.optional_field(
    "redirect_uris",
    [],
    decode.list(uri_field_decoder),
  )
  use software_statement <- decode.optional_field(
    "software_statement",
    option.None,
    decode.optional(decode.string),
  )
  use token_endpoint_auth_method <- decode.optional_field(
    "token_endpoint_auth_method",
    option.None,
    decode.optional(decode.then(
      decode.string,
      token_endpoint_auth_method_decoder,
    )),
  )
  use grant_types <- decode.optional_field(
    "grant_types",
    [],
    decode.list(decode.then(decode.string, grant_type_decoder)),
  )
  use response_types <- decode.optional_field(
    "response_types",
    [],
    decode.list(decode.then(decode.string, response_type_decoder)),
  )
  use client_name <- decode.optional_field(
    "client_name",
    option.None,
    decode.optional(decode.string),
  )
  use client_name_localized <- decode.then(localized_decoder(
    fields,
    "client_name",
    decode.string,
  ))
  use client_uri <- decode.optional_field(
    "client_uri",
    option.None,
    decode.optional(uri_field_decoder),
  )
  use client_uri_localized <- decode.then(localized_decoder(
    fields,
    "client_uri",
    uri_field_decoder,
  ))
  use logo_uri <- decode.optional_field(
    "logo_uri",
    option.None,
    decode.optional(uri_field_decoder),
  )
  use logo_uri_localized <- decode.then(localized_decoder(
    fields,
    "logo_uri",
    uri_field_decoder,
  ))
  use scope <- decode.optional_field(
    "scope",
    option.None,
    decode.optional(decode.string),
  )
  let scope = scope |> option.map(common.parse_scope) |> option.unwrap([])
  use contacts <- decode.optional_field(
    "contacts",
    [],
    decode.list(decode.string),
  )
  use tos_uri <- decode.optional_field(
    "tos_uri",
    option.None,
    decode.optional(uri_field_decoder),
  )
  use tos_uri_localized <- decode.then(localized_decoder(
    fields,
    "tos_uri",
    uri_field_decoder,
  ))
  use policy_uri <- decode.optional_field(
    "policy_uri",
    option.None,
    decode.optional(uri_field_decoder),
  )
  use policy_uri_localized <- decode.then(localized_decoder(
    fields,
    "policy_uri",
    uri_field_decoder,
  ))
  use jwks <- decode.then(jwks_location_decoder())
  use software_id <- decode.optional_field(
    "software_id",
    option.None,
    decode.optional(decode.string),
  )
  use software_version <- decode.optional_field(
    "software_version",
    option.None,
    decode.optional(decode.string),
  )
  decode.success(ClientMetadata(
    redirect_uris:,
    software_statement:,
    token_endpoint_auth_method:,
    grant_types:,
    response_types:,
    client_name:,
    client_name_localized:,
    client_uri:,
    client_uri_localized:,
    logo_uri:,
    logo_uri_localized:,
    scope:,
    contacts:,
    tos_uri:,
    tos_uri_localized:,
    policy_uri:,
    policy_uri_localized:,
    jwks:,
    software_id:,
    software_version:,
  ))
}

pub fn client_metadata_to_json(client_metadata: ClientMetadata) -> Json {
  let ClientMetadata(
    redirect_uris:,
    software_statement:,
    token_endpoint_auth_method:,
    grant_types:,
    response_types:,
    client_name:,
    client_name_localized:,
    client_uri:,
    client_uri_localized:,
    logo_uri:,
    logo_uri_localized:,
    scope:,
    contacts:,
    tos_uri:,
    tos_uri_localized:,
    policy_uri:,
    policy_uri_localized:,
    jwks:,
    software_id:,
    software_version:,
  ) = client_metadata
  let localized_client_names =
    client_name_localized
    |> prefix_keys("client_name", _, json.string)
  let localized_client_uris =
    client_uri_localized |> prefix_keys("client_uri", _, uri_to_json)
  let localized_logo_uris =
    logo_uri_localized |> prefix_keys("logo_uri", _, uri_to_json)
  let localized_tos_uris =
    tos_uri_localized |> prefix_keys("tos_uri", _, uri_to_json)
  let localized_policy_uris =
    policy_uri_localized |> prefix_keys("policy_uri", _, uri_to_json)
  let scope = {
    scope
    |> list.is_empty()
    |> bool.lazy_guard(return: fn() { option.None }, otherwise: fn() {
      string.join(scope, " ") |> option.Some
    })
  }
  list.new()
  |> json_attach_list_member("redirect_uris", redirect_uris, uri_to_json)
  |> json_attach_member("software_statement", software_statement, json.string)
  |> json_attach_member(
    "token_endpoint_auth_method",
    token_endpoint_auth_method,
    token_endpoint_auth_method_to_json,
  )
  |> json_attach_list_member("grant_types", grant_types, grant_type_to_json)
  |> json_attach_list_member(
    "response_types",
    response_types,
    response_type_to_json,
  )
  |> json_attach_member("client_name", client_name, json.string)
  |> list.append(localized_client_names)
  |> json_attach_member("client_uri", client_uri, uri_to_json)
  |> list.append(localized_client_uris)
  |> json_attach_member("logo_uri", logo_uri, uri_to_json)
  |> list.append(localized_logo_uris)
  |> json_attach_member("scope", scope, json.string)
  |> json_attach_list_member("contacts", contacts, json.string)
  |> json_attach_member("tos_uri", tos_uri, uri_to_json)
  |> list.append(localized_tos_uris)
  |> json_attach_member("policy_uri", policy_uri, uri_to_json)
  |> list.append(localized_policy_uris)
  |> list.append(jwks_to_json(jwks))
  |> json_attach_member("software_id", software_id, json.string)
  |> json_attach_member("software_version", software_version, json.string)
  |> json.object()
}

pub type JwksLocation {
  ByValue(value: JwkSet)
  ByUri(value: Uri)
  NoJwks
}

fn jwks_location_decoder() -> decode.Decoder(JwksLocation) {
  use jwks_uri <- decode.optional_field(
    "jwks_uri",
    option.None,
    decode.optional(decode.then(decode.string, uri_decoder)),
  )
  use jwks <- decode.optional_field(
    "jwks",
    option.None,
    decode.optional(jwk.jwk_set_decoder()),
  )
  case jwks_uri, jwks {
    option.None, option.None -> decode.success(NoJwks)
    option.Some(jwks_uri), option.None -> decode.success(ByUri(jwks_uri))
    option.None, option.Some(jwks) -> decode.success(ByValue(jwks))
    option.Some(_), option.Some(_) ->
      decode.failure(NoJwks, "jwks_uri and jwks MUST NOT both be present")
  }
}

fn jwks_to_json(jwks_location: JwksLocation) -> List(#(String, Json)) {
  case jwks_location {
    NoJwks -> []
    ByUri(val) -> [#("jwks_uri", uri_to_json(val))]
    ByValue(val) -> [#("jwks", jwk.jwk_set_to_json(val))]
  }
}

pub type TokenEndpointAuthMethod {
  NoAuthMethod
  ClientSecretPost
  ClientSecretBasic
  OtherTokenEndpointAuthMethod(name: String)
}

fn token_endpoint_auth_method_decoder(
  name: String,
) -> decode.Decoder(TokenEndpointAuthMethod) {
  case name {
    "none" -> decode.success(NoAuthMethod)
    "client_secret_post" -> decode.success(ClientSecretPost)
    "client_secret_basic" -> decode.success(ClientSecretBasic)
    name -> decode.success(OtherTokenEndpointAuthMethod(name:))
  }
}

fn token_endpoint_auth_method_to_json(
  token_endpoint_auth_method: TokenEndpointAuthMethod,
) -> Json {
  case token_endpoint_auth_method {
    NoAuthMethod -> json.string("none")
    ClientSecretPost -> json.string("client_secret_post")
    ClientSecretBasic -> json.string("client_secret_basic")
    OtherTokenEndpointAuthMethod(name:) -> json.string(name)
  }
}

pub type GrantType {
  AuthorizationCode
  Implicit
  Password
  ClientCredentials
  RefreshToken
  UrnIetfParamsOauthGrantTypeJwtBearer
  UrnIetfParamsOauthGrantTypeSaml2Bearer
  OtherGrantType(name: String)
}

fn grant_type_decoder(name: String) -> decode.Decoder(GrantType) {
  case name {
    "authorization_code" -> decode.success(AuthorizationCode)
    "implicit" -> decode.success(Implicit)
    "password" -> decode.success(Password)
    "client_credentials" -> decode.success(ClientCredentials)
    "refresh_token" -> decode.success(RefreshToken)
    "urn:ietf:params:oauth:grant-type:jwt-bearer" ->
      decode.success(UrnIetfParamsOauthGrantTypeJwtBearer)
    "urn:ietf:params:oauth:grant-type:saml2-bearer" ->
      decode.success(UrnIetfParamsOauthGrantTypeSaml2Bearer)
    name -> decode.success(OtherGrantType(name:))
  }
}

fn grant_type_to_json(grant_type: GrantType) -> Json {
  case grant_type {
    AuthorizationCode -> json.string("authorization_code")
    Implicit -> json.string("implicit")
    Password -> json.string("password")
    ClientCredentials -> json.string("client_credentials")
    RefreshToken -> json.string("refresh_token")
    UrnIetfParamsOauthGrantTypeJwtBearer ->
      json.string("urn:ietf:params:oauth:grant-type:jwt-bearer")
    UrnIetfParamsOauthGrantTypeSaml2Bearer ->
      json.string("urn:ietf:params:oauth:grant-type:saml2-bearer")
    OtherGrantType(name:) -> json.string(name)
  }
}

pub type ResponseType {
  Code
  Token
  OtherResponseType(name: String)
}

fn response_type_decoder(name: String) -> decode.Decoder(ResponseType) {
  case name {
    "code" -> decode.success(Code)
    "token" -> decode.success(Token)
    name -> decode.success(OtherResponseType(name:))
  }
}

fn response_type_to_json(response_type: ResponseType) -> Json {
  case response_type {
    Code -> json.string("code")
    Token -> json.string("token")
    OtherResponseType(name:) -> json.string(name)
  }
}

fn prefix_keys(
  unlocalized_name: String,
  localized_dict: Dict(String, a),
  to_json: fn(a) -> Json,
) -> List(#(String, Json)) {
  localized_dict
  |> dict.to_list()
  |> list.map(fn(pair) {
    let #(key, val) = pair
    #(unlocalized_name <> "#" <> key, to_json(val))
  })
}

fn localized_decoder(
  fields: Dict(String, dynamic.Dynamic),
  name: String,
  value_decoder: decode.Decoder(a),
) -> decode.Decoder(Dict(String, a)) {
  let prefix = name <> "#"
  let keys =
    dict.keys(fields)
    |> list.filter(fn(key) { string.starts_with(key, prefix) })
  use pairs <- decode.then(
    list.fold(keys, decode.success([]), fn(acc, key) {
      use pairs <- decode.then(acc)
      use value <- decode.field(key, value_decoder)
      decode.success([
        #(string.drop_start(key, string.length(prefix)), value),
        ..pairs
      ])
    }),
  )
  decode.success(dict.from_list(pairs))
}
