-module(netspire_config).

-export([start/0, get_option/1]).

-include("netspire.hrl").

-define(NETSPIRE_CONFIG, "./netspire.conf").

%% @doc Loading configuration file
%% The configuration file should be specified using
%% NETSPIRE_CONFIG shell variable or by passing 'config' option to the erl emulator
%% If both variables were not defined then function
%% will attempt to open netspire.conf file in the current directory
%% In case when the configuration is already loaded
%% the function will erase all the entries and load the new ones
%% @end
start() ->
    case ets:info(config) of
        undefined -> % configuration table does not exists, creating it
            ets:new(config, [named_table]);
        _ -> % remove all entries and reload configuration
            ets:delete_all_objects(config)
    end,
    Config = case os:getenv("NETSPIRE_CONFIG") of
        false ->
            case application:get_env(config) of
                undefined -> ?NETSPIRE_CONFIG;
                {ok, File} -> File
            end;
        File -> File
    end,
    load_file(Config).

%% @doc Looking for the value for the specific option
%% Returns the option value or 'undefined' atom in case if the option does not exists
%% @end
get_option(Option) ->
    case ets:lookup(config, Option) of
        [{Option, Value}] -> Value;
        _ -> undefined
    end.

%%
%% Internal functions
%%
load_file(File) ->
    ?INFO_MSG("Loading configuration file ~s~n", [File]),
    case file:consult(File) of
        {ok, Terms} ->
            ets:insert(config, Terms);
        {error, Reason} ->
            Msg = file:format_error(Reason),
            ?ERROR_MSG("Can't load configuration file ~s: ~s~n", [File, Msg]),
            exit(Reason)
    end.
