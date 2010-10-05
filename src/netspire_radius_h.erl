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
    case netspire_hooks:run_fold(radius_access_request, undefined, [Request, Client]) of
        {auth, {Password, Replies, Context}} ->
            do_auth(Request, Password, Replies, Context, Client);
        {accept, Replies, Context} ->
            do_access_accept(Request, Replies, Context, Client);
        {reject, Replies, Context} ->
            do_access_reject(Request, Replies, Context, Client);
        _Any ->
            do_access_reject(Request, [], undefined, Client)
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

do_auth(Request, Password, Replies, Context, Client) ->
    UserName = radius:attribute_value("User-Name", Request),
    Args = [Request, UserName, Password, Replies, Client],
    case netspire_hooks:run_fold(radius_auth, undefined, Args) of
        {accept, NewReplies} ->
            do_access_accept(Request, NewReplies, Context, Client);
        {reject, NewReplies} ->
            do_access_reject(Request, NewReplies, Context, Client);
        {challenge, NewReplies} ->
            do_access_challenge(Request, NewReplies, Context, Client);
        _Any ->
            do_access_reject(Request, [], Context, Client)
    end.

do_access_accept(Request, Replies, Context, Client) ->
    Response = #radius_packet{code = ?ACCESS_ACCEPT, attrs = Replies},
    case netspire_hooks:run_fold(radius_access_accept, Response, [Request, Context, Client]) of
        {reject, NewReplies} ->
            do_access_reject(Request, NewReplies, Context, Client);
        NewResponse ->
            {ok, NewResponse}
    end.

do_access_challenge(Request, Replies, Context, Client) ->
    Response = #radius_packet{code = ?ACCESS_CHALLENGE, attrs = Replies},
    netspire_hooks:run(radius_access_challenge, [Response, Request, Context, Client]),
    {ok, Response}.

do_access_reject(Request, Replies, Context, Client) ->
    Response = #radius_packet{code = ?ACCESS_REJECT, attrs = Replies},
    netspire_hooks:run(radius_access_reject, [Response, Request, Context, Client]),
    {ok, Response}.

do_accounting(Args) ->
    case netspire_hooks:run_fold(radius_acct_request, noreply, Args) of
        noreply ->
            noreply;
        Response ->
            {ok, Response}
    end.
