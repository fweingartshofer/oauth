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
gleam add flwr_oauth2@2.0.0
```

```gleam
import flwr_oauth2 as oauth2
import gleam/httpc
import gleam/uri

pub fn main() -> Nil {
  let assert Ok(server) =
    uri.parse(
      "http://localhost:8080/realms/OAuth/protocol/openid-connect/token",
    )
  let token_request =
    oauth2.ClientCredentialsGrantTokenRequest(
      server,
      oauth2.ClientSecretPost(
        oauth2.ClientId("credentials-client"),
        oauth2.Secret("client-secret"),
      ),
      ["openid"],
    )
  let assert Ok(req) = oauth2.to_http_request(token_request)

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
- [ ] [RFC7521](https://datatracker.ietf.org/doc/html/)
  - [ ] [RFC7522 SAML Profile Authorization Grant Kind](https://datatracker.ietf.org/doc/html/rfc7522)
  - [x] [RFC7523 JWT Profile Authorization Grant Kind](https://datatracker.ietf.org/doc/html/rfc7523)
- [ ] [RFC7591 Dynamic Client Creation](https://datatracker.ietf.org/doc/html/rfc7591)
- [x] [RFC7636 PKCE Extension for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc7636)
