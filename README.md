# OAuth2.0

An oauth 2.0 library that does not assume anything.
The library can be used to produce OAuth 2.0 requests and parse token responses.
It produces gleam http requests and takes in gleam http responses.

<!--[![Package Version](https://img.shields.io/hexpm/v/oauth2)](https://hex.pm/packages/oauth2)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/oauth2/)

```sh
gleam add oauth2@1
```-->

```gleam
import oauth2
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

<!--Further documentation can be found at <https://hexdocs.pm/oauth2>.-->

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```
