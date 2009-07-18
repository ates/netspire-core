-module(mod_ippool).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/0,
         info/0,
         allocate/1,
         add_framed_ip/3,
         free_framed_ip/4]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("../netspire.hrl").
-include("../netspire_radius.hrl").
-include("../radius/radius.hrl").

-define(SERVER, ?MODULE).

-record(state, {}).
-record(ippool_entry, {ip, pool, in_use = false}).

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    ChildSpec = {?SERVER,
                 {?MODULE, start_link, []},
                 temporary,
                 1000,
                 worker,
                 [?MODULE]},
    supervisor:start_child(netspire_sup, ChildSpec),
    case proplists:get_value(allocate, Options, true) of
        false ->
            ok;
        true ->
            mnesia:clear_table(ippool),
            ?INFO_MSG("### Cleaning up ippool ###~n", []),
            Pools = proplists:get_value(pools, Options, []),
            mod_ippool:allocate(Pools)
    end.

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    gen_server:call(?SERVER, stop),
    supervisor:terminate_child(netspire_sup, ?SERVER),
    supervisor:delete_child(netspire_sup, ?SERVER).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

allocate(Pools) ->
    gen_server:call(?MODULE, {allocate, Pools}).

lease(Pool) ->
    gen_server:call(?MODULE, {lease, Pool}).

free(IP) ->
    gen_server:cast(?MODULE, {free, IP}).

info() ->
    gen_server:call(?MODULE, info).

add_framed_ip(Response, _Request, _Client) ->
    Pool = gen_module:get_option(?MODULE, default, main),
    case lease(Pool) of
        false ->
            ?WARNING_MSG("### No more free ip addresses ###~n", []),
            {stop, {reject, []}};
        {value, IP} ->
            ?INFO_MSG("### Adding Framed-IP-Address ~p ###~n", [IP]),
            Attrs = Response#radius_packet.attrs,
            Response#radius_packet{attrs = [{?FRAMED_IP_ADDRESS, IP} | Attrs]}
    end.

free_framed_ip(Response, 2, Request, _Client) ->
    IP = radius:attribute_value(?FRAMED_IP_ADDRESS, Request),
    ?INFO_MSG("### Freeing Framed-IP-Address ~p ###~n", [IP]),
    free(IP),
    Response;
free_framed_ip(Response, _, _, _) ->
    Response.

%%%
%%% Internal functions
%%%

init([]) ->
    mnesia:create_table(ippool, [{disc_copies, [node()]},
                                 {record_name, ippool_entry},
                                 {attributes, record_info(fields, ippool_entry)}]),
    mnesia:add_table_copy(ippool, node(), disc_copies),
    netspire_hooks:add(radius_access_accept, ?MODULE, add_framed_ip),
    netspire_hooks:add(radius_acct_request, ?MODULE, free_framed_ip),
    {ok, #state{}}.

handle_call({allocate, Pools}, _From, State) ->
    ?INFO_MSG("### Allocating ip pool ###~n", []),
    lists:foreach(fun add_pool/1, Pools),
    {reply, ok, State};
handle_call({lease, Pool}, _From, State) ->
    MatchHead = #ippool_entry{ip = '$1', pool = Pool, in_use = false},
    F = fun() ->
                case mnesia:select(ippool, [{MatchHead, [], ['$1']}]) of
                    [] ->
                        false;
                    Result ->
                        IP = hd(Result),
                        Rec = #ippool_entry{ip = IP, pool = Pool, in_use = true},
                        mnesia:write(ippool, Rec, write),
                        {value, IP}
                end
        end,
    case mnesia:transaction(F) of
        {atomic, Result} ->
            {reply, Result, State};
        {aborted, Reason} ->
            ?WARNING_MSG("Cannot lease Framed-IP-Address due ~p~n", [Reason]),
            {reply, false, State}
    end;
handle_call(info, _From, State) ->
    F = fun(Key) -> mnesia:dirty_read({ippool, Key}) end,
    Result = lists:map(F, mnesia:dirty_all_keys(ippool)),
    {reply, Result, State};
handle_call(stop, _From, State) ->
    netspire_hooks:delete(radius_auth_response, ?MODULE, add_framed_ip),
    netspire_hooks:delete(radius_acct_request, ?MODULE, free_framed_ip),
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast({free, IP}, State) ->
    F = fun() ->
                case mnesia:read({ippool, IP}) of
                    [Rec] ->
                        Entry = Rec#ippool_entry{in_use = false},
                        mnesia:write(ippool, Entry, write);
                    _ ->
                        ok
                end
        end,
    case mnesia:transaction(F) of
        {atomic, _} ->
            {noreply, State};
        {aborted, Reason} ->
            ?WARNING_MSG("Cannot release Framed-IP-Address ~s "
                         "due ~p~n", [inet_parse:ntoa(IP), Reason]),
            {noreply, State}
    end;
handle_cast(_Request, State) ->
    {noreply, State}.

add_pool({Pool, Ranges}) ->
    lists:foreach(fun(Range) -> add_range(Pool, Range) end, Ranges).
add_range(Pool, {First, Last} = _Range) ->
    {ok, {I1, I2, I3, I4}} = inet_parse:address(First),
    {ok, {_, _, _, I8}} = inet_parse:address(Last),
    F = fun(N) ->
                IP = {I1, I2, I3, N},
                Rec = #ippool_entry{pool = Pool, ip = IP, in_use = false},
                mnesia:dirty_write(ippool, Rec)
        end,
    lists:foreach(F, lists:seq(I4, I8)).

handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.
