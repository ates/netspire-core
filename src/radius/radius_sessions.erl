-module(radius_sessions).

%% API
-export([init_mnesia/0,
         get_inactive/0,
         is_exist/1,
         fetch/1,
         prepare/3,
         prepare/4,
         start/3,
         start/4,
         update/2,
         interim/2,
         interim/3,
         stop/2,
         stop/3,
         expire/0,
         expire/1,
         purge/1]).


-include("radius.hrl").
-include("../netspire.hrl").
-include_lib("stdlib/include/qlc.hrl").

init_mnesia() ->
    mnesia:create_table(session, [{disc_copies, [node()]},
                                  {attributes, record_info(fields, session)}]),
    mnesia:add_table_copy(session, node(), disc_copies).

is_exist(UserName) ->
    F = fun(S) ->
            (S#session.status == new
                orelse S#session.status == active)
                andalso S#session.username == UserName
        end,
    F1 = fun() ->
            Q = qlc:q([S || S <- mnesia:table(session), F(S)]),
            qlc:e(Q)
         end,
    case mnesia:activity(async_dirty, F1) of
        [] ->
            false;
        _ ->
            true
    end.

fetch(SID) ->
    mnesia:dirty_read(session, SID).

prepare(UserName, IP, Timeout) ->
    prepare(UserName, IP, Timeout, undefined).
prepare(UserName, IP, Timeout, Data) ->
    Now = netspire_util:timestamp(),
    ExpiresAt = Now + Timeout,
    SID = {Now, UserName},
    S = #session{id = SID,
                 ip = IP,
                 status = new,
                 username = UserName,
                 started_at = Now,
                 expires_at = ExpiresAt,
                 data = Data},
    F = fun() -> mnesia:write(S), S end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            ?INFO_MSG("Session prepared for ~s~n", [UserName]),
            {ok, Result};
        {aborted, Reason} ->
            Msg = "An error occured while preparing session for ~s~n",
            ?ERROR_MSG(Msg, [UserName]),
            {error, Reason}
    end.

start(UserName, SID, ExpiresAt) ->
    start(UserName, SID, ExpiresAt, fun(P) -> P end).

start(UserName, SID, ExpiresAt, Fun) ->
    Pattern = {session, '_', '_', UserName, new, '_', '_', '_', '_', '_'},
    F = fun() ->
            case mnesia:match_object(session, Pattern, write) of
                [S] ->
                    mnesia:delete_object(S),
                    S1 = S#session{id = SID, status = active, expires_at = ExpiresAt},
                    S2 = Fun(S1),
                    mnesia:write(S2),
                    S2;
                _ ->
                    mnesia:abort(bad_session_match)
            end
        end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            ?INFO_MSG("Session ~s started for ~s~n", [SID, UserName]),
            {ok, Result};
        {aborted, Reason} ->
            Msg = "An error occured while starting session ~s for ~s~n",
            ?ERROR_MSG(Msg, [SID, UserName]),
            {error, Reason}
    end.

update(SID, Fun) ->
    F = fun() ->
            case mnesia:read(session, SID, write) of
                [S] ->
                    S1 = Fun(S),
                    mnesia:write(S1),
                    S1;
                _ ->
                    mnesia:abort(not_found)
            end
        end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            {ok, Result};
        {aborted, Reason} ->
            {error, Reason}
    end.

interim(SID, ExpiresAt) ->
    interim(SID, ExpiresAt, fun(P) -> P end).

interim(SID, ExpiresAt, Fun) ->
    Pattern = {session, SID, '_', '_', active, '_', '_', '_', '_', '_'},
    F = fun() ->
            [S] = mnesia:match_object(session, Pattern, write),
            S1 = S#session{expires_at = ExpiresAt},
            S2 = Fun(S1),
            mnesia:write(S2),
            S2
        end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            UserName = Result#session.username,
            ?INFO_MSG("Session ~s updated for ~s~n", [SID, UserName]),
            {ok, Result};
        {aborted, Reason} ->
            Msg = "An error occured while updating session ~s~n",
            ?ERROR_MSG(Msg, [SID]),
            {error, Reason}
    end.

stop(SID, FinishedAt) ->
    stop(SID, FinishedAt, fun(P) -> P end).

stop(SID, FinishedAt, Fun) ->
    F = fun() ->
            [S] = mnesia:read(session, SID, write),
            S1 = S#session{status = stopped, finished_at = FinishedAt},
            S2 = Fun(S1),
            mnesia:write(S2),
            S2
        end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            ?INFO_MSG("Session ~s stopped~n", [SID]),
            {ok, Result};
        {aborted, Reason} ->
            Msg = "An error occured while stopping session ~s~n",
            ?ERROR_MSG(Msg, [SID]),
            {error, Reason}
    end.

expire() ->
    Now = netspire_util:timestamp(),
    expire(Now).

expire(Time) ->
    F = fun(S) ->
            (S#session.status == new orelse S#session.status == active)
                andalso S#session.expires_at =< Time
        end,
    F1 = fun(S) ->
            S1 = S#session{status = expired},
            mnesia:write(S1),
            S1
         end,
    F2 = fun() ->
            Q = qlc:q([S || S <- mnesia:table(session), F(S)]),
            mnesia:lock({table, session}, write),
            lists:map(F1, qlc:e(Q))
         end,
    case mnesia:transaction(F2) of
        {atomic, Result} ->
            L = length(Result),
            ?INFO_MSG("~p session(s) has been expired successfully~n", [L]),
            {ok, Result};
        {aborted, Reason} ->
            ?ERROR_MSG("An error occured while expiring session(s)~n", []),
            {error, Reason}
    end.

get_inactive() ->
    F = fun(S) ->
            S#session.status == stopped
                orelse S#session.status == expired
        end,
    Q = qlc:q([S || S <- mnesia:table(session), F(S)]),
    mnesia:activity(async_dirty, fun() -> qlc:e(Q) end).

purge(S) ->
    mnesia:dirty_delete_object(S).
