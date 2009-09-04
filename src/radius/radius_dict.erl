%%%----------------------------------------------------------------------
%%% File : radius_dict.erl
%%% Purpose : Provides RADIUS dictionary.
%%%----------------------------------------------------------------------
-module(radius_dict).
-behaviour(gen_server).

-export([start_link/0, lookup_attribute/1, lookup_value/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("radius.hrl").
-include("../netspire.hrl").

-define(ATTRS_TABLE, radius_dict_attrs).
-define(VALUES_TABLE, radius_dict_values).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init(_Args) ->
    process_flag(trap_exit, true),
    ?INFO_MSG("Starting module ~p~n", [?MODULE]),
    ets:new(?ATTRS_TABLE, [named_table, {keypos, 2}]),
    ets:new(?VALUES_TABLE, [named_table]),
    load_dictionary("dictionary"),
    {ok, empty}.

load_dictionary(File) ->
    case file:open(dictionary_path(File), [read]) of
        {ok, Fd} ->
            read_line(Fd);
        {error, enoent} ->
            ok
    end.

dictionary_path(File) ->
    PrivDir = case code:priv_dir(netspire) of
        {error, bad_name} ->
	        "./priv";
        D ->
            D
    end,
    filename:join([PrivDir, "radius", File]).

read_line(Fd) ->
    case io:get_line(Fd, "") of
        eof ->
            file:close(Fd);
        Line ->
            L = strip_comments(Line),
            case parse_line(string:tokens(L, "\t\n\s")) of
                {attribute, A} ->
                    ets:insert(?ATTRS_TABLE, [A]),
                    read_line(Fd);
                {value, V} ->
                    Key = {V#value.aname, V#value.value},
                    ets:insert(?VALUES_TABLE, [{Key, V}]),
                    read_line(Fd);
                _ ->
                    read_line(Fd)
            end
    end.

strip_comments(Line) ->
    case string:chr(Line, $#) of
        0 ->
            Line;
        I ->
            L = string:sub_string(Line, 1, I - 1),
            string:strip(L)
    end.

parse_line(["$INCLUDE", File]) ->
    load_dictionary(File);

parse_line(["ATTRIBUTE", Name, Code, Type]) ->
    A = #attribute{name = Name, code = list_to_integer(Code), type = list_to_atom(Type)},
    {attribute, A};

parse_line(["ATTRIBUTE", Name, Code, Type, Extra]) ->
    case get({vendor, Extra}) of
        undefined ->
            T = string:tokens(Extra, ","),
            Opts = lists:map(fun(I) -> parse_option(string:tokens(I, "=")) end, T),
            A = #attribute{name = Name, code = list_to_integer(Code), type = list_to_atom(Type)},
            {attribute, A#attribute{opts = Opts}};
        Vendor ->
            C = {Vendor, list_to_integer(Code)},
            A = #attribute{name = Name, code = C, type = list_to_atom(Type)},
            {attribute, A}
    end;

parse_line(["VALUE", A, Name, Value]) ->
    V = #value{aname = A, vname = Name, value = list_to_integer(Value)},
    {value, V};

parse_line(["VENDOR", Name, Code]) ->
    put({vendor, Name}, list_to_integer(Code));

parse_line(_) ->
    ok.

parse_option(["has_tag"]) ->
    has_tag;

parse_option(["encrypt", Value]) ->
    {encrypt, list_to_integer(Value)}.

lookup_attribute(Name) when is_list(Name) ->
    Pat = {attribute, '_', '_', Name, '_'},
    case ets:match_object(?ATTRS_TABLE, Pat, 1) of
        {[Attr], _} ->
            Attr;
        '$end_of_table' ->
            not_found
    end;
lookup_attribute(Code) ->
    case ets:lookup(?ATTRS_TABLE, Code) of
        [Attr] ->
            Attr;
        [] ->
            not_found
    end.

lookup_value(A, V) ->
    case ets:lookup(?VALUES_TABLE, {A, V}) of
        [{_Key, Value}] ->
            Value;
        [] ->
            not_found
    end.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
