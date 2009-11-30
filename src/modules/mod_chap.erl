-module(mod_chap).

-behaviour(gen_module).

%% API
-export([verify_chap/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("../netspire.hrl").
-include("../netspire_radius.hrl").
-include("../radius/radius.hrl").

-define(CHAP_PASSWORD, 3).
-define(CHAP_CHALLENGE, 60).

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    netspire_hooks:add(radius_auth, ?MODULE, verify_chap).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_chap).

verify_chap(_, Request, UserName, Password, Replies, _Client) ->
    case radius:attribute_value(?CHAP_PASSWORD, Request) of
        undefined -> undefined;
        UserPassword ->
            case radius:attribute_value(?CHAP_CHALLENGE, Request) of
                undefined -> undefined;
                Challenge ->
                    ChapPassword = list_to_binary(UserPassword),
                    do_chap(UserName, ChapPassword, Challenge, Password, Replies)
            end
    end.

do_chap(UserName, <<ChapId, ChapPassword/binary>>, Challenge, Password, Replies) ->
    PasswordHash = erlang:md5([ChapId, Password, Challenge]),
    case PasswordHash == ChapPassword of
        true ->
            ?INFO_MSG("CHAP authentication succeeded: ~p~n", [UserName]),
            {stop, {accept, Replies}};
        _ ->
            ?INFO_MSG("CHAP authentication failed: ~p~n", [UserName]),
            {stop, {reject, []}}
    end.

