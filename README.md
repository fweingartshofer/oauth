# OAuth2.0

An oauth 2.0 library that does not assume anything.
The library can be used to produce OAuth 2.0 requests and parse token responses.
It produces gleam http requests and takes in gleam http responses.
Use whatever http client you prefer for either javascript or erlang.
The library pulls in as few dependencies as possible to maintain
compatibility with as many use cases as possible.

[![Package Version](https://img.shields.io/hexpm/v/flwr_oauth2)](https://hex.pm/packages/flwr_oauth2)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/flwr_oauth2/)

```sh
gleam add flwr_oauth2@3.0.0
```

```gleam
import flwr_oauth2/authentication
import flwr_oauth2/common
import flwr_oauth2/token_request
import gleam/httpc
import gleam/uri

pub fn main() -> Nil {
  let assert Ok(token_endpoint) =
    uri.parse(
      "http://localhost:8080/realms/OAuth/protocol/openid-connect/token",
    )
  let token_req =
    token_request.ClientCredentialsGrantTokenRequest(
      token_endpoint,
      authentication.ClientSecretPost(
        common.ClientId("credentials-client"),
        common.Secret("client-secret"),
      ),
      ["openid"],
    )
  let assert Ok(req) = token_request.to_http_request(token_req)

  let res = httpc.send(req)
  echo res
}
```

Further documentation can be found at <https://hexdocs.pm/flwr_oauth2>

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```

## Roadmap

OAuth 2.0 includes many different RFC which define and extend it.
This package aims to implement the most common ones.

- [x] [RFC6749 OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749).
- [x] [RFC6750 Bearer Token Authorization for Resource Servers](https://datatracker.ietf.org/doc/html/rfc6750)
- [x] [RFC7009 Revocation of Tokens](https://datatracker.ietf.org/doc/html/rfc7009)
- [x] [RFC7521](https://datatracker.ietf.org/doc/html/)
  - [x] [RFC7522 SAML Profile Authorization Grant Kind](https://datatracker.ietf.org/doc/html/rfc7522)
  - [x] [RFC7523 JWT Profile Authorization Grant Kind](https://datatracker.ietf.org/doc/html/rfc7523)
- [ ] [RFC7591 Dynamic Client Creation](https://datatracker.ietf.org/doc/html/rfc7591)
- [x] [RFC7636 PKCE Extension for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc7636)
- [x] Parsing and serializing of [RFC7517 JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)

