-module(integration_http_ffi).
-export([send/2]).

send(Request, Callback) ->
    case 'gleam@hackney':send(Request) of
        {ok, Response} -> Callback({ok, Response});
        {error, _Reason} -> Callback({error, nil})
    end.
