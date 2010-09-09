%%%----------------------------------------------------------------------
%%% File : netspire_radius_h.erl
%%% Purpose : RADIUS request handler.
%%%----------------------------------------------------------------------
-module(netspire_radius_h).

-behaviour(gen_radius).

%% gen_radius callbacks
-export([process_request/3]).

-include("netspire.hrl").
-include("radius/radius.hrl").

process_request('Access-Request', Request, Client) ->
    case radius:attribute_value("User-Name", Request) of
        undefined ->
            ?WARNING_MSG("Missing required attribute User-Name, "
                         "replying Access-Reject~n", []),
            {ok, #radius_packet{code = ?ACCESS_REJECT}};
        UserName ->
            do_auth([Request, UserName, Client])
    end;
process_request('Accounting-Request', Request, Client) ->
    case radius:attribute_value("Acct-Status-Type", Request) of
        undefined ->
            ?WARNING_MSG("Missing required attribute Acct-Status-Type, "
                         "discarding request~n", []),
            noreply;
        StatusType ->
            do_accounting([StatusType, Request, Client])
    end;
process_request(_Type, Request, Client) ->
    netspire_hooks:run_fold(radius_request, noreply, [Request, Client]).

do_auth([Request, UserName, Client] = Args) ->
    case netspire_hooks:run_fold(radius_acct_lookup, undefined, Args) of
        {ok, {Password, Replies, Extra}} ->
            NewArgs = [Request, UserName, Password, Replies, Client],
            case netspire_hooks:run_fold(radius_auth, undefined, NewArgs) of
                {accept, Attrs} ->
                    do_access_accept(Request, Attrs, Extra, Client);
                {reject, Attrs} ->
                    do_access_reject(Request, Attrs, Client);
                _Any ->
                    {ok, #radius_packet{code = ?ACCESS_REJECT}}
            end;
        undefined ->
            {ok, #radius_packet{code = ?ACCESS_REJECT}}
    end.

do_access_accept(Request, Attrs, Extra, Client) ->
    Response = #radius_packet{code = ?ACCESS_ACCEPT, attrs = Attrs},
    case netspire_hooks:run_fold(radius_access_accept, Response, [Request, Extra, Client]) of
        {reject, NewAttrs} ->
            do_access_reject(Request, NewAttrs, Client);
        NewResponse ->
            {ok, NewResponse}
    end.

do_access_reject(Request, Attrs, Client) ->
    Response = #radius_packet{code = ?ACCESS_REJECT, attrs = Attrs},
    netspire_hooks:run(radius_access_reject, [Request, Response, Client]),
    {ok, Response}.

do_accounting(Args) ->
    case netspire_hooks:run_fold(radius_acct_request, noreply, Args) of
        noreply ->
            noreply;
        Response ->
            {ok, Response}
    end.
