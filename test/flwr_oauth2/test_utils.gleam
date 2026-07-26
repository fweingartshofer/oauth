import gleam/http
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option
import gleam/string

pub fn request_to_string(req: request.Request(String)) -> String {
  let method = http.method_to_string(req.method)
  let scheme = http.scheme_to_string(req.scheme)
  let port =
    req.port
    |> option.map(int.to_string)
    |> option.unwrap("")
  let query =
    req.query
    |> option.map(fn(q) { "?" <> q })
    |> option.unwrap("")
  let headers =
    req.headers
    |> list.map(fn(h) { h.0 <> ": " <> h.1 })
    |> string.join("\n")

  method
  <> " "
  <> scheme
  <> "://"
  <> req.host
  <> port
  <> req.path
  <> query
  <> "\n"
  <> headers
  <> "\n"
  <> "\n"
  <> req.body
}
