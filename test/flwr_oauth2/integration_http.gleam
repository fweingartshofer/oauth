import gleam/http/request.{type Request}
import gleam/http/response.{type Response}

/// Returns synchronously on Erlang and as a Promise on JavaScript.
pub type RequestTask

@external(erlang, "integration_http_ffi", "send")
@external(javascript, "./integration_http_ffi.mjs", "send")
pub fn send(
  request: Request(String),
  callback: fn(Result(Response(String), Nil)) -> Nil,
) -> RequestTask
