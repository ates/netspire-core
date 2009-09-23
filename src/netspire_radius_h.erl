%%%----------------------------------------------------------------------
%%% File : netspire_radius_h.erl
%%% Purpose : RADIUS request handler.
%%%----------------------------------------------------------------------
-module(netspire_radius_h).

-behaviour(gen_radius).

%% gen_radius callbacks
-export([process_request/3]).

-include("netspire.hrl").
-include("netspire_radius.hrl").
-include("radius/radius.hrl").

process_request('Access-Request', Request, Client) ->
    case radius:attribute_value(?USER_NAME, Request) of
        undefined ->
            ?WARNING_MSG("Missing required attribute User-Name, "
                         "replying Access-Reject~n", []),
            {ok, #radius_packet{code = ?ACCESS_REJECT}};
        UserName ->
            do_auth([Request, UserName, Client])
    end;
process_request('Accounting-Request', Request, Client) ->
    case radius:attribute_value(?ACCT_STATUS_TYPE, Request) of
        undefined ->
            ?WARNING_MSG("Missing required attribute Acct-Status-Type, "
                         "discarding request~n", []),
            noreply;
        StatusType ->
            do_acct([StatusType, Request, Client])
    end;
process_request(_Type, Request, Client) ->
    netspire_hooks:run_fold(radius_request, noreply, [Request, Client]).

do_auth([Request, UserName, Client] = Args) ->
    case netspire_hooks:run_fold(radius_acct_lookup, undefined, Args) of
        {ok, {Password, Replies, Extra}} ->
            Args1 = [Request, UserName, Password, Replies, Client],
            case netspire_hooks:run_fold(radius_auth, undefined, Args1) of
                {accept, Attrs} ->
                    do_accept(Request, Attrs, Extra, Client);
                {reject, Attrs} ->
                    do_reject(Request, Attrs, Client);
                _Any ->
                    {ok, #radius_packet{code = ?ACCESS_REJECT}}
            end;
        undefined ->
            {ok, #radius_packet{code = ?ACCESS_REJECT}}
    end.

do_accept(Request, Attrs, Extra, Client) ->
    Response = #radius_packet{code = ?ACCESS_ACCEPT, attrs = Attrs},
    case netspire_hooks:run_fold(radius_access_accept, Response, [Request, Extra, Client]) of
        {reject, Attrs1} ->
            do_reject(Request, Attrs1, Client);
        Response1 ->
            {ok, Response1}
    end.

do_reject(Request, Attrs, Client) ->
    Response = #radius_packet{code = ?ACCESS_REJECT, attrs = Attrs},
    netspire_hooks:run(radius_access_reject, [Request, Response, Client]),
    {ok, Response}.

do_acct([_StatusType, _Request, _Client] = Args) ->
    Response = #radius_packet{code = ?ACCT_RESPONSE},
    case netspire_hooks:run_fold(radius_acct_request, Response, Args) of
        noreply ->
            noreply;
        Response1 ->
            {ok, Response1}
    end.
