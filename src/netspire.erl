-module(netspire).
-behaviour(application).

-export([start/2, stop/1]).

-include("netspire.hrl").

start(normal, _StartArgs) ->
    ?INFO_MSG("Starting application ~p~n", [?MODULE]),
    init_mnesia(),
    netspire_config:start(),
    init_logging(),
    connect_nodes(),
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
    case mnesia:system_info(extra_db_nodes) of
        [] ->
            mnesia:create_schema([node()]);
        _ ->
            ok
    end,
    mnesia:start(),
    mnesia:wait_for_tables(mnesia:system_info(local_tables), infinity).

connect_nodes() ->
    case netspire_config:get_option(nodes) of
        Nodes when is_list(Nodes) andalso Nodes /= [] ->
            lists:foreach(fun(Node) -> 
                        net_kernel:connect_node(Node) end, Nodes),
            ?INFO_MSG("Connected nodes: ~p~n", [nodes()]);
        _ ->
            ok
    end.

init_logging() ->
    case netspire_config:get_option(logging) of
        {Module, Opts} ->
            ?INFO_MSG("Starting logging system: ~p~n", [Module]),
            error_logger:add_report_handler(Module, Opts);
        _ -> ?ERROR_MSG("Invalid logging options~n", [])
    end.
