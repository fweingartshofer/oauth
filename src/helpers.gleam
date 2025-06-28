import gleam/list
import gleam/string

pub fn list_not_empty(l: List(a)) -> Bool {
  !list.is_empty(l)
}

pub fn string_not_empty(l: String) -> Bool {
  !string.is_empty(l)
}
