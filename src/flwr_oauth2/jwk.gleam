/// This module implements [RFC7517 JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
import gleam/dynamic/decode.{type Decoder}
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option}
import gleam/uri.{type Uri}

pub type JwkSet {
  JwkSet(keys: List(JsonWebKey))
}

pub fn jwk_set_decoder() -> Decoder(JwkSet) {
  use keys <- decode.field("keys", decode.list(json_web_key_decoder()))
  decode.success(JwkSet(keys:))
}

pub fn jwk_set_to_json(jwk_set: JwkSet) -> Json {
  let JwkSet(keys:) = jwk_set
  json.object([
    #("keys", json.array(keys, json_web_key_to_json)),
  ])
}

pub type JsonWebKey {
  JsonWebKey(
    key: Key,
    public_key_use: Option(PublicKeyUse),
    key_ops: List(KeyOperation),
    alg: Option(Algorithm),
    kid: Option(String),
    x5u: Option(Uri),
    x5c: List(String),
    x5t: Option(String),
    x5t_s256: Option(String),
  )
}

pub fn json_web_key_decoder() -> Decoder(JsonWebKey) {
  use key <- decode.then(key_decoder())
  use public_key_use <- decode.optional_field(
    "use",
    option.None,
    decode.optional(decode.then(decode.string, public_key_use_decoder)),
  )
  use key_ops <- decode.optional_field(
    "key_ops",
    [],
    decode.list(decode.then(decode.string, key_operation_decoder)),
  )
  use alg <- decode.optional_field(
    "alg",
    option.None,
    decode.optional(decode.then(decode.string, algorithm_decoder)),
  )
  use kid <- decode.optional_field(
    "kid",
    option.None,
    decode.optional(decode.string),
  )
  use x5u <- decode.optional_field(
    "x5u",
    option.None,
    decode.optional(decode.then(decode.string, uri_decoder)),
  )
  use x5c <- decode.optional_field("x5c", [], decode.list(decode.string))
  use x5t <- decode.optional_field(
    "x5t",
    option.None,
    decode.optional(decode.string),
  )
  use x5t_s256 <- decode.optional_field(
    "x5t#S256",
    option.None,
    decode.optional(decode.string),
  )
  decode.success(JsonWebKey(
    key:,
    public_key_use:,
    key_ops:,
    alg:,
    kid:,
    x5u:,
    x5c:,
    x5t:,
    x5t_s256:,
  ))
}

pub fn json_web_key_to_json(json_web_key: JsonWebKey) -> Json {
  let JsonWebKey(
    key:,
    public_key_use:,
    key_ops:,
    alg:,
    kid:,
    x5u:,
    x5c:,
    x5t:,
    x5t_s256:,
  ) = json_web_key
  key_to_json(key)
  |> json_attach_member("use", public_key_use, public_key_use_to_json)
  |> json_attach_list_member("key_ops", key_ops, key_operation_to_json)
  |> json_attach_member("alg", alg, algorithm_to_json)
  |> json_attach_member("kid", kid, json.string)
  |> json_attach_member("x5u", x5u, fn(x5u) { json.string(uri.to_string(x5u)) })
  |> json_attach_list_member("x5c", x5c, json.string)
  |> json_attach_member("x5t", x5t, json.string)
  |> json_attach_member("x5t#S256", x5t_s256, json.string)
  |> json.object()
}

pub type Key {
  RsaKey(n: String, e: String)
  EcKey(crv: String, x: String, y: String)
  OctKey(k: String)
  OtherKey(kty: String)
}

fn key_decoder() -> Decoder(Key) {
  use kty <- decode.field("kty", decode.string)
  case kty {
    "RSA" -> {
      use n <- decode.field("n", decode.string)
      use e <- decode.field("e", decode.string)
      decode.success(RsaKey(n:, e:))
    }
    "EC" -> {
      use crv <- decode.field("crv", decode.string)
      use x <- decode.field("x", decode.string)
      use y <- decode.field("y", decode.string)
      decode.success(EcKey(crv:, x:, y:))
    }
    "oct" -> {
      use k <- decode.field("k", decode.string)
      decode.success(OctKey(k:))
    }
    kty -> {
      decode.success(OtherKey(kty:))
    }
  }
}

fn key_to_json(key: Key) -> List(#(String, Json)) {
  case key {
    RsaKey(n:, e:) -> [
      #("kty", json.string("RSA")),
      #("n", json.string(n)),
      #("e", json.string(e)),
    ]
    EcKey(crv:, x:, y:) -> [
      #("kty", json.string("EC")),
      #("crv", json.string(crv)),
      #("x", json.string(x)),
      #("y", json.string(y)),
    ]
    OctKey(k:) -> [
      #("kty", json.string("oct")),
      #("k", json.string(k)),
    ]
    OtherKey(kty:) -> {
      [
        #("kty", json.string(kty)),
      ]
    }
  }
}

/// Corresponds to the [kty (Key Type) Parameter Values](https://datatracker.ietf.org/doc/html/rfc7518#section-6.1)
pub type PublicKeyUse {
  Signature
  Encryption
  OtherUse(value: String)
}

fn public_key_use_decoder(use_: String) -> Decoder(PublicKeyUse) {
  case use_ {
    "sig" -> decode.success(Signature)
    "enc" -> decode.success(Encryption)
    value -> decode.success(OtherUse(value:))
  }
}

fn public_key_use_to_json(public_key_use: PublicKeyUse) -> Json {
  case public_key_use {
    Signature -> json.string("sig")
    Encryption -> json.string("enc")
    OtherUse(value:) -> json.string(value)
  }
}

pub type KeyOperation {
  Sign
  Verify
  Encrypt
  Decrypt
  WrapKey
  UnwrapKey
  DeriveKey
  DeriveBits
  OtherKeyOperation(value: String)
}

fn key_operation_decoder(key_operation: String) -> Decoder(KeyOperation) {
  case key_operation {
    "sign" -> decode.success(Sign)
    "verify" -> decode.success(Verify)
    "encrypt" -> decode.success(Encrypt)
    "decrypt" -> decode.success(Decrypt)
    "wrapKey" -> decode.success(WrapKey)
    "unwrapKey" -> decode.success(UnwrapKey)
    "deriveKey" -> decode.success(DeriveKey)
    "deriveBits" -> decode.success(DeriveBits)
    value -> decode.success(OtherKeyOperation(value:))
  }
}

fn key_operation_to_json(key_operation: KeyOperation) -> Json {
  case key_operation {
    Sign -> json.string("sign")
    Verify -> json.string("verify")
    Encrypt -> json.string("encrypt")
    Decrypt -> json.string("decrypt")
    WrapKey -> json.string("wrapKey")
    UnwrapKey -> json.string("unwrapKey")
    DeriveKey -> json.string("deriveKey")
    DeriveBits -> json.string("deriveBits")
    OtherKeyOperation(value:) -> json.string(value)
  }
}

/// Some of the more common algorithms used for JWKS, but can be extended
pub type Algorithm {
  RS256
  ES256
  PS256
  HS256
  None
  OtherAlgorithm(value: String)
}

fn algorithm_decoder(alg: String) -> Decoder(Algorithm) {
  case alg {
    "RS256" -> decode.success(RS256)
    "ES256" -> decode.success(ES256)
    "PS256" -> decode.success(PS256)
    "HS256" -> decode.success(HS256)
    "none" -> decode.success(None)
    value -> decode.success(OtherAlgorithm(value))
  }
}

fn algorithm_to_json(algorithm: Algorithm) -> Json {
  case algorithm {
    RS256 -> json.string("RS256")
    ES256 -> json.string("ES256")
    PS256 -> json.string("PS256")
    HS256 -> json.string("HS256")
    None -> json.string("none")
    OtherAlgorithm(value:) -> json.string(value)
  }
}

fn uri_decoder(raw_uri: String) -> Decoder(Uri) {
  case uri.parse(raw_uri) {
    Ok(x5u) -> decode.success(x5u)
    _ -> decode.failure(uri.empty, "Invalid URI")
  }
}

fn json_attach_member(
  entries: List(#(String, Json)),
  name: String,
  value: Option(a),
  to_json: fn(a) -> Json,
) -> List(#(String, Json)) {
  case value |> option.map(to_json) {
    option.Some(value) -> list.append(entries, [#(name, value)])
    option.None -> entries
  }
}

fn json_attach_list_member(
  entries: List(#(String, Json)),
  name: String,
  values: List(a),
  to_json: fn(a) -> Json,
) -> List(#(String, Json)) {
  case values {
    [] -> entries
    _ -> list.append(entries, [#(name, json.array(values, to_json))])
  }
}
