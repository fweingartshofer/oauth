import birdie
import flwr_oauth2/http_headers
import gleam/http/request
import gleeunit/should

pub fn set_basic_encodes_correctly_test() {
  // Given
  let client_id = "Client ID!"
  let client_secret = "$'(client+secret)~ "

  // When
  let res = http_headers.set_basic(request.new(), client_id, client_secret)

  // Then
  res
  |> request.get_header("authorization")
  |> should.be_ok()
  |> birdie.snap(
    "set_basic encodes special characters correctly for form encoding",
  )
}
