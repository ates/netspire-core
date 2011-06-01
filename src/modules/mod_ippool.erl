-module(mod_ippool).

-behaviour(gen_module).

%% API
-export([info/0,
         allocate/1,
         add_framed_ip/1,
         renew_framed_ip/1,
         release_framed_ip/1]).

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
    netspire_hooks:add(ippool_lease_ip, ?MODULE, add_framed_ip),
    netspire_hooks:add(ippool_renew_ip, ?MODULE, renew_framed_ip),
    netspire_hooks:add(ippool_release_ip, ?MODULE, release_framed_ip).

allocate(Pools) ->
    ?INFO_MSG("Allocating ip pools~n", []),
    lists:foreach(fun add_pool/1, Pools).

add_pool({Pool, Ranges}) ->
    lists:foreach(fun(Range) -> add_range(Pool, Range) end, Ranges).
add_range(Pool, Range) ->
    F = fun(IP) ->
            Rec = #ippool_entry{pool = Pool, ip = IP},
            mnesia:dirty_write(ippool, Rec)
    end,
    lists:foreach(F, iplib:range2list(Range)).

lease(Pool) ->
    Timeout = gen_module:get_option(?MODULE, timeout, ?TIMEOUT),
    Now = netspire_util:timestamp(),
    ExpiresAt = Now + Timeout,
    MatchHead = #ippool_entry{ip = '$1', pool = Pool, expires_at = '$3'},
    MatchSpec = [{MatchHead, [{'=<', '$3', Now}], ['$1']}],
    F = fun() ->
            case mnesia:select(ippool, MatchSpec, 1, write) of
                '$end_of_table' ->
                    case gen_module:get_option(?MODULE, use_another_one_free_pool) of
                        yes ->
                            MatchHead1 = #ippool_entry{ip = '_', pool = '$1', expires_at = 0},
                            MatchSpec1 = [{MatchHead1, [], ['$1']}],
                            FreePools = mnesia:dirty_select(ippool, MatchSpec1),
                            try
                                FreePool = lists:nth(1, FreePools),
                                lease(FreePool)
                            catch
                                _:_ ->
                                    {error, empty}
                            end;
                        _ ->
                            {error, empty}
                    end;
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

add_framed_ip({reject, _} = Response) ->
    Response;
add_framed_ip(Response) ->
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
                    ?INFO_MSG("Adding Framed-IP-Address ~s~n", [inet_parse:ntoa(IP)]),
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

renew_framed_ip(Request) ->
    IP = radius:attribute_value("Framed-IP-Address", Request),
    case renew(IP) of
        {ok, _} ->
            ?INFO_MSG("Framed-IP-Address ~s is renewed~n", [inet_parse:ntoa(IP)]);
        {error, not_found} ->
            ok;
        {error, Reason} ->
            ?WARNING_MSG("Cannot renew Framed-IP-Address ~s"
                "due to ~p~n", [inet_parse:ntoa(IP), Reason])
    end.

release_framed_ip(Request) ->
    IP = radius:attribute_value("Framed-IP-Address", Request),
    case mnesia:dirty_read({ippool, IP}) of
        [Rec] ->
            ?INFO_MSG("Release Framed-IP-Address ~s~n", [inet_parse:ntoa(IP)]),
            Entry = Rec#ippool_entry{expires_at = 0},
            mnesia:dirty_write(ippool, Entry);
        _ -> ok
    end.


stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete_all(?MODULE).
