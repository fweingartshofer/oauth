//// Helper functions

import gleam/list
import gleam/option

/// Appends the value if present a given list
pub fn add_if_present(d: List(a), value: option.Option(a)) -> List(a) {
  [value]
  |> option.values
  |> list.append(d)
}

pub fn unwrap_both(res: Result(a, a)) -> a {
  case res {
    Ok(res) -> res
    Error(res) -> res
  }
}
