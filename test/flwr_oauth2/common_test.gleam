import flwr_oauth2/common
import gleeunit
import gleeunit/should

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn parse_scope_with_two_scopes_test() {
  // Given
  let scope = "scope1 scope2"

  // When
  let res = common.parse_scope(scope)

  // Then
  res |> should.equal(["scope1", "scope2"])
}

pub fn parse_scope_with_extra_spaces_test() {
  // Given
  let scope = " scope1  scope2 "

  // When
  let res = common.parse_scope(scope)

  // Then
  res |> should.equal(["scope1", "scope2"])
}

pub fn parse_scope_with_empty_string_test() {
  // Given
  let scope = "  "

  // When
  let res = common.parse_scope(scope)

  // Then
  res |> should.equal([])
}
