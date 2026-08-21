import flwr_oauth2/jwk
import gleam/json
import gleeunit/should

pub fn jwks_is_parsed_correctly_test() {
  // Given
  let json =
    "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"},{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}]}"
  // When
  let assert Ok(parsed) = json.parse(json, jwk.jwk_set_decoder())

  // Then
  parsed
  |> jwk.jwk_set_to_json()
  |> json.to_string()
  |> should.equal(json)
}

pub fn jwks_with_custom_key_and_custom_algorithm_parsed_correctly_test() {
  // Given
  let json =
    "{\"keys\":[{\"kty\":\"cstm\",\"use\":\"enc\",\"key_ops\":[\"encrypt\"],\"alg\":\"custom-alg\",\"kid\":\"1\"}]}"
  // When
  let assert Ok(parsed) = json.parse(json, jwk.jwk_set_decoder())

  // Then
  parsed
  |> jwk.jwk_set_to_json()
  |> json.to_string()
  |> should.equal(json)
}

pub fn jwks_with_x5_parsed_correctly_test() {
  // Given
  let json =
    "{\"keys\":[{\"kty\":\"cstm\",\"use\":\"enc\",\"key_ops\":[\"encrypt\"],\"alg\":\"custom-alg\",\"kid\":\"1\",\"x5u\":\"https://example.com/x5u\",\"x5c\":[\"x5c-string\"],\"x5t\":\"x5t-string\",\"x5t#S256\":\"x5t#S256-string\"}]}"
  // When
  let assert Ok(parsed) = json.parse(json, jwk.jwk_set_decoder())

  // Then
  parsed
  |> jwk.jwk_set_to_json()
  |> json.to_string()
  |> should.equal(json)
}

pub fn jwks_with_invalid_x5u_fails_test() {
  // Given
  let json =
    "{\"keys\":[{\"kty\":\"cstm\",\"use\":\"enc\",\"key_ops\":[\"encrypt\"],\"alg\":\"custom-alg\",\"kid\":\"1\",\"x5u\":\"::::::\"}]}"
  // When
  let res = json.parse(json, jwk.jwk_set_decoder())

  // Then
  res |> should.be_error()
}

pub fn jwks_with_missing_members_fails_test() {
  // Given
  let json =
    "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"enc\",\"key_ops\":[\"encrypt\"],\"alg\":\"custom-alg\",\"kid\":\"1\"}]}"
  // When
  let res = json.parse(json, jwk.jwk_set_decoder())

  // Then
  res |> should.be_error()
}
