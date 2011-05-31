-module(netspire).

-behaviour(application).

-export([start/2, stop/1, uptime/0]).

-include("netspire.hrl").

start(normal, _StartArgs) ->
    netspire_logger:start(),
    ?INFO_MSG("Starting application ~p~n", [?MODULE]),
    ok = init_mnesia(),
    netspire_config:start(),
    crypto:start(),
    gen_module:start(),
    Sup = netspire_sup:start_link(),
    case netspire_config:get_option(code_path) of
        undefined -> ok;
        Path ->
            code:add_pathsz(Path)
    end,
    start_services(),
    start_modules(),
    Sup.

stop(_State) ->
    ?INFO_MSG("Application ~p has stopped~n", [?MODULE]).

%% @doc Returns how long the system has been running
uptime() ->
    {T, _} = erlang:statistics(wall_clock),
    calendar:seconds_to_daystime(erlang:trunc(T / 1000)).

%%
%% Internal API
%%
init_mnesia() ->
    ?INFO_MSG("Checking availability of cluster environment~n", []),
    Nodes = case net_adm:host_file() of
        {error, _} -> [];
        _ ->
            [N || N <- net_adm:world(), N =/= node()]
    end,
    case Nodes of
        [] ->
            ?INFO_MSG("No additional nodes were found~n", []),
            mnesia:create_schema([node()]),
            mnesia:start();
        _ ->
            ?INFO_MSG("Connected nodes: ~p~n", [Nodes]),
            mnesia:change_config(extra_db_nodes, Nodes),
            mnesia:start(),
            ok = waiting_for_tables()
    end.

waiting_for_tables() ->
    Tables = [Tab || Tab <- mnesia:system_info(tables), mnesia:table_info(Tab, local_content) =:= false],
    case mnesia:wait_for_tables(Tables, 30000) of
        ok -> ok;
        {timeout, Tabs} ->
            throw({error, {timeout_waiting_for_tables, Tabs}});
        {error, Reason} ->
            throw({error, {failed_waiting_for_tables, Reason}})
    end.

start_services() ->
    Fun = fun({Module, Options}) ->
            Module:start(Options)
    end,
    case netspire_config:get_option(services) of
        undefined -> ok;
        Services ->
            lists:foreach(Fun, Services)
    end.

start_modules() ->
    Fun = fun({Module, Options}) ->
            gen_module:start_module(Module, Options)
    end,
    case netspire_config:get_option(modules) of
        undefined -> ok;
        Modules ->
            lists:foreach(Fun, Modules)
    end.
