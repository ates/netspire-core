-module(gen_module).

-export([start/0,
         start_module/2,
         stop_module/1,
         restart_module/2,
         loaded_modules/0,
         loaded_modules_with_options/0,
         get_option/2,
         get_option/3,
         is_loaded/1]).

-export([behaviour_info/1]).

-include("netspire.hrl").

-record(netspire_module, {id, opts}).

-define(MODULES_TABLE, netspire_modules).

behaviour_info(callbacks) ->
    [{start, 1}, {stop, 0}];
behaviour_info(_) ->
    undefined.

start() ->
    ?INFO_MSG("Starting module ~p~n", [?MODULE]),
    ets:new(?MODULES_TABLE, [named_table, public, {keypos, 2}]),
    ok.

start_module(Module, Options) ->
    case ets:lookup(?MODULES_TABLE, Module) of
        [] ->
            try Module:start(Options) of
                _ ->
                    Rec = #netspire_module{id = Module, opts = Options},
                    ets:insert(?MODULES_TABLE, Rec),
                    ok
            catch
                _:Reason ->
                    ?ERROR_MSG("Error while starting module ~p: ~p~n", [Module, Reason]),
                    {error, Reason}
            end;
        _ ->
            ?WARNING_MSG("Dynamic module ~p already started~n", [Module]),
            {error, already_started}
    end.

stop_module(Module) ->
    case ets:lookup(?MODULES_TABLE, Module) of
        [] ->
            ?WARNING_MSG("Dynamic module ~p was not started~n", [Module]),
            {error, not_started};
        _ ->
            safely_stop_module(Module)
    end.

safely_stop_module(Module) ->
    try Module:stop() of
        {wait, ProcList} when is_list(ProcList) ->
            lists:foreach(fun wait_for_process/1, ProcList),
            ets:delete(?MODULES_TABLE, Module),
            ok;
        {wait, Process} ->
            wait_for_process(Process),
            ets:delete(?MODULES_TABLE, Module),
            ok;
        _ ->
            ets:delete(?MODULES_TABLE, Module),
            ok
    catch
        exit:Reason ->
            ?ERROR_MSG("Error while stopping module due to ~p", [Reason]),
            {error, Reason}
    end.

restart_module(Module, NewOptions) ->
    case is_loaded(Module) of
        false ->
            start_module(Module, NewOptions);
        _ ->
            stop_module(Module),
            start_module(Module, NewOptions)
    end.

wait_for_process(Process) ->
    MonRef = erlang:monitor(process, Process),
    wait_for_stop(Process, MonRef).

wait_for_stop(Process, MonRef) ->
    receive
        {'DOWN', MonRef, _Type, _Object, _Info} ->
            ok
    after 5000 ->
            catch exit(whereis(Process), kill),
            wait_for_kill(MonRef)
    end.

wait_for_kill(MonRef) ->
    receive
        {'DOWN', MonRef, _Type, _Object, _Info} ->
            ok
    after 5000 ->
            ok
    end.

get_option(Module, Name) ->
    get_option(Module, Name, undefined).
get_option(Module, Name, Default) ->
    case ets:lookup(?MODULES_TABLE, Module) of
        [] ->
            Default;
        [#netspire_module{opts = Options}] ->
            proplists:get_value(Name, Options, Default)
    end.

is_loaded(Module) ->
    ets:member(?MODULES_TABLE, Module).

loaded_modules() ->
    ets:select(?MODULES_TABLE, [{{'_','$1','_'}, [], ['$1']}]).

loaded_modules_with_options() ->
    ets:select(?MODULES_TABLE, [{{'_','$1','$2'}, [], [{{'$1', '$2'}}]}]).
