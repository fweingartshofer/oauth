//// Helper functions

import gleam/list
import gleam/option

/// Appends the value if present a given list
pub fn add_if_present(d: List(a), value: option.Option(a)) -> List(a) {
  [value]
  |> option.values
  |> list.append(d)
}
