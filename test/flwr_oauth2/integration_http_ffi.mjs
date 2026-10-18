import {
  send as fetch_send,
  read_text_body,
} from "../../gleam_fetch/gleam/fetch.mjs";
import {
  Result$isError,
  Result$Error,
  Result$Ok,
  Result$Ok$0,
} from "../gleam.mjs";

export function send(request, callback) {
  return fetch_send(request).then(
    response => {
      if (Result$isError(response)) {
        return callback(Result$Error(undefined));
      }

      return read_text_body(Result$Ok$0(response)).then(
        body => {
          if (Result$isError(body)) {
            return callback(Result$Error(undefined));
          }

          return callback(Result$Ok(Result$Ok$0(body)));
        },
        () => callback(Result$Error(undefined)),
      );
    },
    () => callback(Result$Error(undefined)),
  );
}
