%%%----------------------------------------------------------------------
%%% File : gen_radius.erl
%%% Purpose : Provides functions for building RADIUS servers.
%%%----------------------------------------------------------------------
-module(gen_radius).

-behaviour(gen_server).

%% API
-export([start_link/4, add_request_handler/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-export([behaviour_info/1]).

-include("../netspire.hrl").
-include("radius.hrl").

-record(state, {socket, port, clients}).

behaviour_info(callbacks) ->
    [{process_request, 3}];
behaviour_info(_) ->
    undefined.

start_link(Name, Port, IP, Family) ->
    gen_server:start_link({local, Name}, ?MODULE, [Port, IP, Family], []).

init([Port, IP, Family]) ->
    process_flag(trap_exit, true),
    SocketOpts = [binary, Family, {ip, IP}, {active, once}],
    case gen_udp:open(Port, SocketOpts) of
        {ok, Socket} ->
            ?INFO_MSG("Starting module ~p on ~s:~p~n", [?MODULE, inet_parse:ntoa(IP), Port]),
            case ets:info(?MODULE) of
                undefined ->
                    ets:new(?MODULE, [named_table, public]);
                _Info ->
                    ok
            end,
            Clients = ets:new(clients, [{keypos, 2}]),
            {ok, #state{socket = Socket, port = Port, clients = Clients}};
        {error, Reason} ->
            ?ERROR_MSG("Unable to start ~p: ~s~n", [?MODULE, inet:format_error(Reason)]),
            {stop, Reason}
    end.

add_request_handler(ServerRef, {Name, IP, Secret, Module}) ->
    Client = #nas_spec{ip = IP, name = Name, secret = Secret, module = Module},
    gen_server:call(ServerRef, {add_nas_handler, Client}).

handle_call({add_nas_handler, Spec}, _From, State) ->
    ets:insert(State#state.clients, Spec),
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, SrcIP, SrcPort, Bin}, State) ->
    case radius:decode_packet(Bin) of
        {ok, Packet} ->
            case request_exists(SrcIP, SrcPort, Packet) of
                false ->
                    Pid = spawn_link(fun() ->
                                             handle_packet(SrcIP, SrcPort, Socket, Packet, State)
                                     end),
                    store_request(SrcIP, SrcPort, Packet, Pid),
                    inet:setopts(Socket, [{active, once}]),
                    {noreply, State};
                true ->
                    inet:setopts(Socket, [{active, once}]),
                    {noreply, State}
            end;
        {error, invalid} ->
            ?WARNING_MSG("Invalid packet from NAS: ~s~n", [inet_parse:ntoa(SrcIP)]),
            inet:setopts(Socket, [{active, once}]),
            {noreply, State}
    end;
handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};
handle_info({'EXIT', Pid, _Reason}, State) ->
    sweep_request(Pid),
    {noreply, State}.

terminate(_Reason, State) ->
    gen_udp:close(State#state.socket).

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_packet(SrcIP, SrcPort, Socket, Packet, State) ->
    case lookup_client(SrcIP, State#state.clients) of
        {ok, Client} ->
            do_callback(SrcIP, SrcPort, Socket, Client, Packet);
        undefined ->
            ?WARNING_MSG("Request from unknown client: ~s~n", [inet_parse:ntoa(SrcIP)])
    end.

do_callback(IP, Port, Socket, Client, Packet) ->
    case radius:identify_packet(Packet#radius_packet.code) of
        {ok, Type} ->
            Module = Client#nas_spec.module,
            case Module:process_request(Type, Packet, Client) of
                {ok, Response} ->
                    do_reply(Socket, IP, Port, Response, Packet, Client),
                    sweep_request(IP, Port, Packet);
                noreply ->
                    sweep_request(IP, Port, Packet);
                Unknown ->
                    ?ERROR_MSG("Bad return from request handler: ~p~n", [Unknown])
            end;
        {unknown, Unknown} ->
            ?WARNING_MSG("Unknown request type: ~p~n", [Unknown]),
            sweep_request(IP, Port, Packet)
    end.

do_reply(Socket, IP, Port, Response, Request, Client) ->
    Secret = Client#nas_spec.secret,
    case radius:encode_response(Request, Response, Secret) of
        {ok, Data} ->
            gen_udp:send(Socket, IP, Port, Data);
        Error ->
            ?ERROR_MSG("Unable to respond to client due to ~p~n", [Error])
    end.

store_request(IP, Port, Packet, Pid) ->
    Ident = Packet#radius_packet.ident,
    ets:insert(?MODULE, {{IP, Port, Ident}, Pid}).

sweep_request(Pid) ->
    case ets:match_object(?MODULE, {'_', Pid}) of
        [{{IP, Port, Ident}, Pid}] ->
            ets:delete(?MODULE, {IP, Port, Ident});
        [] -> ok
    end.

sweep_request(IP, Port, Packet) ->
    Ident = Packet#radius_packet.ident,
    ets:delete(?MODULE, {IP, Port, Ident}).

request_exists(IP, Port, Packet) ->
    Ident = Packet#radius_packet.ident,
    case ets:lookup(?MODULE, {IP, Port, Ident}) of
        [] ->
            false;
        [_] ->
            true
    end.

lookup_client(IP, Table) ->
    case ets:lookup(Table, IP) of
        [] ->
            undefined;
        [Client] ->
            {ok, Client}
    end.
