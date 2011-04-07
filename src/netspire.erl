-module(netspire).
-behaviour(application).

-export([start/2, stop/1, uptime/0]).

-include("netspire.hrl").

start(normal, _StartArgs) ->
    ?INFO_MSG("Starting application ~p~n", [?MODULE]),
    ok = init_mnesia(),
    netspire_config:start(),
    init_logging(),
    crypto:start(),
    gen_module:start(),
    Sup = netspire_sup:start_link(),
    case netspire_config:get_option(code_path) of
        undefined ->
            ok;
        Path ->
            code:add_pathsz(Path)
    end,
    start_services(),
    start_modules(),
    Sup.

stop(_State) ->
    ?INFO_MSG("Application ~p has stopped~n", [?MODULE]).

uptime() ->
    {T, _} = erlang:statistics(wall_clock),
    calendar:seconds_to_daystime(erlang:trunc(T / 1000)).

%%
%% Internal API
%%
start_services() ->
    Fun = fun({Module, Options}) ->
                Module:start(Options)
          end,
    case netspire_config:get_option(services) of
        undefined ->
            ok;
        Services ->
            lists:foreach(Fun, Services)
    end.

start_modules() ->
    Fun = fun({Module, Options}) ->
                  gen_module:start_module(Module, Options)
          end,
    case netspire_config:get_option(modules) of
        undefined ->
            ok;
        Modules ->
            lists:foreach(Fun, Modules)
    end.

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
            mnesia:start(),
            mnesia:change_config(extra_db_nodes, Nodes)
    end,
    mnesia:wait_for_tables(mnesia:system_info(local_tables), infinity),
    mnesia:change_table_copy_type(schema, node(), disc_copies),
    wait_for_extra_db_nodes(Nodes, 10).

wait_for_extra_db_nodes(_, 0) ->
    ?WARNING_MSG("Failed to synchronize extra_db_nodes~n", []),
    {error, mnesia_timeout};
wait_for_extra_db_nodes(Nodes, N) when N > 0 ->
    case Nodes -- mnesia:system_info(db_nodes) of
        [] -> ok;
        _ ->
            receive after 1000 -> ok end,
            wait_for_extra_db_nodes(Nodes, N - 1)
    end.

init_logging() ->
    case netspire_config:get_option(logging) of
        {Module, Opts} ->
            ?INFO_MSG("Starting logging system: ~p~n", [Module]),
            error_logger:add_report_handler(Module, Opts);
        _ -> ?ERROR_MSG("Invalid logging options~n", [])
    end.
