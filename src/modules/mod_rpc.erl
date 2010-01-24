-module(mod_rpc).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/1]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-include("../netspire.hrl").

-record(state, {socket}).

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    ChildSpec = {?MODULE,
                 {?MODULE, start_link, [Options]},
                 permanent,
                 brutal_kill,
                 worker,
                 [?MODULE]
                },
    supervisor:start_child(netspire_sup, ChildSpec).

stop() ->
    ?INFO_MSG("Stop dynamic module ~p~n", [?MODULE]),
    gen_server:call(?MODULE, stop),
    supervisor:terminate_child(netspire_sup, ?MODULE),
    supervisor:delete_child(netspire_sup, ?MODULE).

start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []).

process_listen_options(Options) ->
    case Options of
        {listen, {Family, StrIP, Port}} ->
            {ok, IP} = inet_parse:address(StrIP),
            SocketOpts = [binary, Family, {ip, IP}, {packet, 4}, {active, false},
                {reuseaddr, true}],
            {ok, {StrIP, Port, SocketOpts}};
        _ ->
            {error, invalid_options}
    end.

loop(LSocket) ->
    case gen_tcp:accept(LSocket) of
        {ok, Socket} ->
            gen_server:cast(?MODULE, {process_request, Socket});
        _ -> ok
    end,
    loop(LSocket).

process_rpc_request(Socket, {call, Mod, Fun, Args}) ->
    try
        Result = apply(Mod, Fun, Args),
        ?INFO_MSG("RPC call: ~p:~p with args ~p~n", [Mod, Fun, Args]),
        gen_tcp:send(Socket, term_to_binary({reply, Result}))
    catch
        Type:Reason ->
            ?ERROR_MSG("RPC call ~p:~p with args ~p failed: ~p~n", [Mod, Fun, Args, {Type, Reason}]),
            gen_tcp:send(Socket, term_to_binary(format_error_reply(Reason)))
    after
        gen_tcp:close(Socket)
    end;
process_rpc_request(Socket, {cast, Mod, Fun, Args}) ->
    gen_tcp:send(Socket, term_to_binary({noreply})),
    ok = gen_tcp:close(Socket),
    try
        ?INFO_MSG("RPC cast: ~p:~p with args ~p~n", [Mod, Fun, Args]),
        apply(Mod, Fun, Args)
    catch
        Type:Reason ->
            ?ERROR_MSG("RPC cast ~p:~p with args ~p failed: ~p~n", [Mod, Fun, Args, {Type, Reason}])
    end.

format_error_reply(Reason) ->
    % TODO: Send predefined error codes if no such module or function
    Fun = fun(I) -> list_to_binary(io_lib:format("~p", [I])) end,
    Backtrace = lists:map(Fun, erlang:get_stacktrace()),
    {error, {server, 100, <<"BERTError">>, Reason, Backtrace}}.

init([Options]) ->
    case process_listen_options(Options) of
        {ok, {StrIP, Port, SocketOpts}} ->
            case gen_tcp:listen(Port, SocketOpts) of
                {ok, Socket} ->
                    ?INFO_MSG("Starting service ~p on ~s:~p~n", [?MODULE, StrIP, Port]),
                    spawn(fun() -> loop(Socket) end),
                    {ok, #state{socket = Socket}};
                {error, Reason} ->
                    ?ERROR_MSG("Cannot listen on ~s:~p due to ~p~n", [StrIP, Port, Reason]),
                    {stop, Reason}
            end;
        {error, Reason} ->
            ?ERROR_MSG("Invalid options for mod_rpc listener: ~p~n", [Options]),
            {stop, Reason}
    end.

handle_cast({process_request, Socket}, State) ->
    case gen_tcp:recv(Socket, 0) of
        {ok, Bin} ->
            Request = binary_to_term(Bin),
            process_rpc_request(Socket, Request);
        {error, closed} ->
            gen_tcp:close(Socket)
    end,
    {noreply, State};
handle_cast(_Request, State) -> {noreply, State}.

handle_info(_Request, State) -> {noreply, State}.

handle_call(_Request, _From, State) -> {reply, ok, State}.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

terminate(_Reason, State) ->
    gen_tcp:close(State#state.socket).
