import flwr_oauth2 as oauth
import gleam/http/request
import gleam/list

/// Attach the access token to the `Authorization` header as Bearer token.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1).
pub fn attach_bearer_token_header(
  req: request.Request(a),
  token: oauth.AccessTokenResponse,
) -> request.Request(a) {
  req
  |> request.set_header(
    oauth.authorization_header,
    "Bearer " <> token.access_token,
  )
}

/// Attach the access token to the body as access token.
/// This function adds the access token to the body of provided request.
/// It does not set the content type to `application/x-www-form-urlencoded`, but in order to send the body with the access token to a server it has to be set and the body needs to be url encoded.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.2).
pub fn attach_access_token_to_body(
  req: request.Request(List(#(String, String))),
  token: oauth.AccessTokenResponse,
) -> request.Request(List(#(String, String))) {
  req.body
  |> list.prepend(access_token_tuple(token))
  |> request.set_body(req, _)
}

/// Attach the access token to the query parameters as access token.
/// See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.3).
pub fn attach_access_token_to_query_parameters(
  req: request.Request(a),
  token: oauth.AccessTokenResponse,
) -> request.Request(a) {
  case request.get_query(req) {
    Error(_) -> []
    Ok(query_params) -> query_params
  }
  |> list.prepend(access_token_tuple(token))
  |> request.set_query(req, _)
}

fn access_token_tuple(token: oauth.AccessTokenResponse) -> #(String, String) {
  #("access_token", token.access_token)
}
