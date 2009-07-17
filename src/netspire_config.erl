-module(netspire_config).
-export([start/0, get_global_option/1, get_option/1]).

-define(NETSPIRE_CONFIG_PATH, "./netspire.conf").

-include("netspire.hrl").

-record(config, {key, value}).
-record(state, {local_opts = [], global_opts = [],
                override_local = false, override_global = false}).

start() ->
    mnesia:create_table(config,
                        [{disc_copies, [node()]},
                         {attributes, record_info(fields, config)}]),
    mnesia:add_table_copy(config, node(), ram_copies),
    mnesia:create_table(local_config,
                        [{disc_copies, [node()]},
                         {record_name, config},
                         {local_content, true},
                         {attributes, record_info(fields, config)}]),
    mnesia:add_table_copy(local_config, node(), ram_copies),
    Config = case application:get_env(config) of
        {ok, Path} -> Path;
        undefined ->
            case os:getenv("NETSPIRE_CONFIG_PATH") of
                false -> ?NETSPIRE_CONFIG_PATH;
                Path -> Path
            end
    end,
    load_file(Config).

get_global_option(Opt) ->
    case ets:lookup(config, Opt) of
        [#config{value = Val}] -> Val;
        _ -> undefined
    end.

get_option(Opt) ->
    case ets:lookup(local_config, Opt) of
        [#config{value = Val}] -> Val;
        _ -> undefined
    end.

%%
%% Internal functions
%%
load_file(File) ->
    ?INFO_MSG("Reading configuration file ~s~n", [File]),
    case file:consult(File) of
        {ok, Terms} ->
            Res = lists:foldl(fun process_term/2, #state{}, Terms),
            write_options(Res);
        {error, Reason} ->
            Msg = file:format_error(Reason),
            ?ERROR_MSG("Can't load config file ~s: ~s~n", [File, Msg]),
            exit(File ++ ": " ++ Msg)
    end.

process_term(Term, State) ->
    case Term of 
        override_global ->
            State#state{override_global = true};
        override_local ->
            State#state{override_local = true};
        {Opt, Val} ->
            add_option(Opt, Val, State)
    end.

add_option(Opt, Val, State) ->
    Local = [#config{key = Opt, value = Val} | State#state.local_opts],
    State#state{local_opts = Local}.

write_options(State) ->
    Local = lists:reverse(State#state.local_opts),
    Global = lists:reverse(State#state.global_opts),
    if
        State#state.override_global ->
            delete_all_options(config);
        true -> ok
    end,
    if
        State#state.override_local ->
            delete_all_options(local_config);
        true -> ok
    end,
    F = fun() ->
        lists:foreach(fun(R) -> mnesia:write(R) end, Global),
        lists:foreach(fun(R) -> mnesia:write(local_config, R, write) end, Local)
    end,
    case mnesia:transaction(F) of
        {atomic, _Result} ->
            ok;
        {aborted, {no_exists, Table}} ->
            ?ERROR_MSG("Error reading Mnesia database spool files for "
                       "the table '~p'~n", [Table])
    end.

delete_all_options(Table) ->
    case Table of
        config ->
            ?INFO_MSG("Purging global configuration options~n", []);
        local_config ->
            ?INFO_MSG("Purging local configuration options~n", [])
    end,
    mnesia:clear_table(Table).
