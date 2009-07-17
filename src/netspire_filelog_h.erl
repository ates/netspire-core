-module(netspire_filelog_h).

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2,
            terminate/2, code_change/3]).

-include("netspire.hrl").
-include_lib("kernel/include/file.hrl").

-define(FILE_OPTIONS, [append, raw]).
-record(state, {fd, file}).

init(Opts) ->
    File = proplists:get_value(path, Opts, []),
    MaxSize = proplists:get_value(max_size, Opts, []),
    RotationInterval = proplists:get_value(rotation_interval, Opts, []),
    init(File, MaxSize, RotationInterval).

init(File, MaxSize, RotationInterval) ->
    case MaxSize of
        0 -> ok;
        Size when Size > 0 ->
            {ok, _T} = timer:send_interval(RotationInterval, self(), 
                {check_log_size, File, Size})
    end,
    case file:open(File, ?FILE_OPTIONS) of
        {ok, Fd} ->
            {ok, #state{fd = Fd, file = File}};
        Error ->
            ?ERROR_MSG("Can't open ~s: ~p", [File, Error])
    end.

handle_event(Event, State) ->
    write_event(State#state.fd, {erlang:localtime(), Event}),
    {ok, State}.

handle_call(_Request, State) ->
    Reply = ok,
    {ok, Reply, State}.

handle_info({check_log_size, File, Size}, State) ->
    case file:read_file_info(File) of
        {ok, FileInfo} when FileInfo#file_info.size > Size ->
            file:close(State#state.fd),
            rotate_log(State#state.file),

            case file:open(File, ?FILE_OPTIONS) of
                {ok, Fd} ->
                    {ok, State#state{fd = Fd}};
                Error ->
                    ?ERROR_MSG("Can't open ~s: ~p", [File, Error])
            end;
        _ ->
            {ok, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, State) ->
    file:close(State#state.fd).

write_event(Fd, {Time, {error, _GL, {Pid, Format, Args}}}) ->
    T = write_time(Time),
    write_msg(Fd, T, Format, Pid, Args);

write_event(Fd, {Time, {error_report, _GL, {Pid, std_error, Rep}}}) ->
    T = write_time(Time),
    write_report(Fd, T, Rep, Pid);

write_event(Fd, {Time, {warning_msg, _GL, {Pid, Format, Args}}}) ->
    T = write_time(Time, "WARNING REPORT"),
    write_msg(Fd, T, Format, Pid, Args);

write_event(Fd, {Time, {warning_report, _GL, {Pid, std_warning, Rep}}}) ->
    T = write_time(Time, "WARNING REPORT"),
    write_report(Fd, T, Rep, Pid);

write_event(Fd, {Time, {info_msg, _GL, {Pid, Format, Args}}}) ->
    T = write_time(Time, "INFO REPORT"),
    write_msg(Fd, T, Format, Pid, Args);

write_event(Fd, {Time, {info_report, _GL, {Pid, std_info, Rep}}}) ->
    T = write_time(Time, "INFO REPORT"),
    write_report(Fd, T, Rep, Pid);

write_event(_, _) ->
    ok.

write_msg(Fd, T, Format, Pid, Args) ->
    case catch io_lib:format(add_node(Format, Pid), Args) of
        S when is_list(S) ->
            file:write(Fd, io_lib:format(T ++ S, []));
        _ ->
            F = add_node("ERROR: ~p - ~p~n", Pid),
            file:write(Fd, io_lib:format(T ++ F, [Format, Args]))
    end.

write_report(Fd, T, Rep, Pid) ->
    S = format_report(Rep),
    file:write(Fd, io_lib:format(T ++ S ++ add_node("", Pid), [])).

format_report(Rep) when is_list(Rep) ->
    case string_p(Rep) of
        true ->
            io_lib:format("~s~n", [Rep]);
        _ ->
            format_rep(Rep)
    end;

format_report(Rep) ->
    io_lib:format("~p~n", [Rep]).

format_rep([{Tag, Data}|Rep]) ->
    io_lib:format(" ~p: ~p~n", [Tag, Data]) ++ format_rep(Rep);

format_rep([Other|Rep]) ->
    io_lib:format(" ~p~n", [Other]) ++ format_rep(Rep);

format_rep(_) ->
    [].

add_node(X, Pid) when is_atom(X) ->
    add_node(atom_to_list(X), Pid);

add_node(X, Pid) when node(Pid) /= node() ->
    lists:concat([X, "** at node ", node(Pid), " **~n"]);

add_node(X, _) ->
    X.

string_p([]) ->
    false;

string_p(Term) ->
    string_p1(Term).

string_p1([H|T]) when is_integer(H), H >= $\s, H < 255 ->
    string_p1(T);

string_p1([$\n|T]) -> string_p1(T);
string_p1([$\r|T]) -> string_p1(T);
string_p1([$\t|T]) -> string_p1(T);
string_p1([$\v|T]) -> string_p1(T);
string_p1([$\b|T]) -> string_p1(T);
string_p1([$\f|T]) -> string_p1(T);
string_p1([$\e|T]) -> string_p1(T);

string_p1([H|T]) when is_list(H) ->
    case string_p1(H) of
        true ->
            string_p1(T);
        _ -> false
    end;

string_p1([]) -> true;
string_p1(_) -> false.

write_time(Time) -> write_time(Time, "ERROR REPORT").

write_time({{Y, Mo, D}, {H, Mi, S}}, Type) ->
    io_lib:format("~n=~s==== ~w-~.2.0w-~.2.0w ~.2.0w:~.2.0w:~.2.0w ===~n",
        [Type, Y, Mo, D, H, Mi, S]).

rotate_log(File) ->
    ?INFO_MSG("Rotating log file: ~s~n", [File]),
    NewName = filename:rootname(File),
    file:rename(File, [NewName, timestamp_suffix(), ".log"]).

timestamp_suffix() ->
    DateTime = lists:flatten(localtime_to_string(erlang:localtime())),
    [Date, Time] = string:tokens(DateTime, " "),
    Suffix = "-" ++ Date ++ "_" ++ Time,
    Suffix.

localtime_to_string({{Year, Month, Day}, {Hour, Minute, Second}}) ->
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w",
        [Year, Month, Day, Hour, Minute, Second]).
