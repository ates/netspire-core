%%% Implementation of CHAP authentication protocol (RFC 1994)
-module(mod_chap).

-behaviour(gen_module).

%% API
-export([verify_chap/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("../netspire.hrl").
-include("../radius/radius.hrl").

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    netspire_hooks:add(radius_auth, ?MODULE, verify_chap).

stop() ->
    ?INFO_MSG("Stop dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_chap).

verify_chap(_, Request, UserName, Password, Replies, _Client) ->
    case radius:attribute_value("CHAP-Password", Request) of
        undefined -> undefined;
        Value ->
            Challenge =
                case radius:attribute_value("Chap-Challenge", Request) of
                	undefined -> Request#radius_packet.auth; 
                    ChapChallenge -> ChapChallenge
                end,
            ChapPassword = list_to_binary(Value),
            do_chap(UserName, ChapPassword, Challenge, Password, Replies)
    end.

do_chap(UserName, <<ChapId, ChapPassword/binary>>, Challenge, Password, Replies) ->
    PasswordHash = crypto:md5([ChapId, Password, Challenge]),
    case PasswordHash == ChapPassword of
        true ->
            ?INFO_MSG("CHAP authentication succeeded: ~p~n", [UserName]),
            {stop, {accept, Replies}};
        _ ->
            ?INFO_MSG("CHAP authentication failed: ~p~n", [UserName]),
            {stop, {reject, []}}
    end.

