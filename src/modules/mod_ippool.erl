-module(mod_ippool).

-behaviour(gen_module).

%% API
-export([info/0,
         allocate/1,
         add_framed_ip/4,
         renew_framed_ip/4]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("../netspire.hrl").
-include("../radius/radius.hrl").

-record(ippool_entry, {ip, pool, expires_at = 0}).

-define(TIMEOUT, 300).

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    mnesia:create_table(ippool, [{disc_copies, [node()]},
                                 {type, ordered_set},
                                 {record_name, ippool_entry},
                                 {attributes, record_info(fields, ippool_entry)}]),
    mnesia:add_table_copy(ippool, node(), disc_copies),
    case proplists:get_value(allocate, Options, true) of
        false ->
            ok;
        true ->
            mnesia:clear_table(ippool),
            ?INFO_MSG("Cleaning up ippool~n", []),
            Pools = proplists:get_value(pools, Options, []),
            mod_ippool:allocate(Pools)
    end,
    netspire_hooks:add(radius_access_accept, ?MODULE, add_framed_ip),
    netspire_hooks:add(radius_acct_request, ?MODULE, renew_framed_ip).

allocate(Pools) ->
    ?INFO_MSG("Allocating ip pools~n", []),
    lists:foreach(fun add_pool/1, Pools).

add_pool({Pool, Ranges}) ->
    lists:foreach(fun(Range) -> add_range(Pool, Range) end, Ranges).
add_range(Pool, {First, Last} = _Range) ->
    {ok, {I1, I2, I3, I4}} = inet_parse:address(First),
    {ok, {_, _, _, I8}} = inet_parse:address(Last),
    F = fun(N) ->
                IP = {I1, I2, I3, N},
                Rec = #ippool_entry{pool = Pool, ip = IP},
                mnesia:dirty_write(ippool, Rec)
        end,
    lists:foreach(F, lists:seq(I4, I8)).

lease(Pool) ->
    Timeout = gen_module:get_option(?MODULE, timeout, ?TIMEOUT),
    Now = netspire_util:timestamp(),
    ExpiresAt = Now + Timeout,
    MatchHead = #ippool_entry{ip = '$1', pool = Pool, expires_at = '$3'},
    MatchSpec = [{MatchHead, [{'=<', '$3', Now}], ['$1']}],
    F = fun() ->
                case mnesia:select(ippool, MatchSpec, 1, write) of
                    '$end_of_table' ->
                        {error, empty};
                    {[IP], _} ->
                        Rec = #ippool_entry{ip = IP, pool = Pool, expires_at = ExpiresAt},
                        mnesia:write(ippool, Rec, write),
                        {ok, IP}
                end
        end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            Result;
        {aborted, Reason} ->
            {error, Reason}
    end.

renew(IP) ->
    Timeout = gen_module:get_option(?MODULE, timeout, ?TIMEOUT),
    Now = netspire_util:timestamp(),
    ExpiresAt = Now + Timeout,
    F = fun() ->
                case mnesia:read({ippool, IP}) of
                    [Rec] ->
                        Entry = Rec#ippool_entry{expires_at = ExpiresAt},
                        mnesia:write(ippool, Entry, write),
                        {ok, IP};
                    _ ->
                        {error, not_found}
                end
        end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            Result;
        {aborted, Reason} ->
            {error, Reason}
    end.

info() ->
    F = fun(Key) -> mnesia:dirty_read({ippool, Key}) end,
    lists:map(F, mnesia:dirty_all_keys(ippool)).

add_framed_ip({reject, _} = Response, _, _, _) ->
    Response;
add_framed_ip(Response, _Request, _Extra, _Client) ->
    case radius:attribute_value("Framed-IP-Address", Response) of
        undefined ->
            Pool = case radius:attribute_value("Netspire-Framed-Pool", Response) of
                undefined ->
                    gen_module:get_option(?MODULE, default, main);
                Value ->
                    list_to_atom(Value)
            end,
            case lease(Pool) of
                {ok, IP} ->
                    ?INFO_MSG("Adding Framed-IP-Address ~p~n", [IP]),
                    Attrs = Response#radius_packet.attrs,
                    Response#radius_packet{attrs = [{"Framed-IP-Address", IP} | Attrs]};
                {error, empty} ->
                    ?WARNING_MSG("No more free ip addresses~n", []),
                    {stop, {reject, []}};
                {error, Reason} ->
                    ?WARNING_MSG("Cannot lease Framed-IP-Address due to ~p~n", [Reason]),
                    {stop, {reject, []}}
            end;
        _ -> Response
    end.

renew_framed_ip(Response, ?INTERIM_UPDATE, Request, _) ->
    IP = radius:attribute_value("Framed-IP-Address", Request),
    case renew(IP) of
        {ok, _} ->
            ?INFO_MSG("Framed-IP-Address ~p is renewed~n", [IP]);
        {error, not_found} ->
            ok;
        {error, Reason} ->
            ?WARNING_MSG("Cannot renew Framed-IP-Address ~s"
                "due ~p~n", [inet_parse:ntoa(IP), Reason])
    end,
    Response;
renew_framed_ip(Response, _, _, _) ->
    Response.

stop() ->
    ?INFO_MSG("Stop dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(radius_auth_response, ?MODULE, add_framed_ip),
    netspire_hooks:delete(radius_acct_request, ?MODULE, free_framed_ip).

