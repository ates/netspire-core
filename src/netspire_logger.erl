-module(netspire_logger).

-export([start/0]).

start() ->
    FileName = case os:getenv("NETSPIRE_LOGFILE") of
        false ->
            case application:get_env(logfile) of
                undefined ->
                    throw({error, no_logfile_is_defined});
                {ok, LogFile} -> LogFile
            end;
        LogFile -> LogFile
    end,
    case filelib:is_regular(FileName) of
        true ->
            NewName = filename:rootname(FileName) ++ timestamp_suffix() ++ ".log",
            ok = file:rename(FileName, NewName);
        false -> ok
    end,
    error_logger:logfile({open, FileName}).

%%
%% Internal functions
%%
timestamp_suffix() ->
    DateTime = lists:flatten(localtime_to_string(erlang:localtime())),
    [Date, Time] = string:tokens(DateTime, " "),
    Suffix = "-" ++ Date ++ "_" ++ Time, Suffix.

localtime_to_string({{Year, Month, Day}, {Hour, Minute, Second}}) ->
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w",
        [Year, Month, Day, Hour, Minute, Second]).
