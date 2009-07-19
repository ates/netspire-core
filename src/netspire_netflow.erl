-module(netspire_netflow).
-behaviour(gen_server).

%% API
-export([start/1,
         start_link/1,
         add_packet_handler/2,
         delete_packet_handler/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-include("netspire.hrl").
-include("netflow/netflow_v5.hrl").
-include("netflow/netflow_v9.hrl").

-record(state, {socket, port, handlers = []}).

start(Options) ->
    ChildSpec = {?MODULE,
                 {?MODULE, start_link, [Options]},
                 permanent,
                 brutal_kill,
                 worker,
                 [?MODULE]
                },
    supervisor:start_child(netspire_sup, ChildSpec).

start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []).

add_packet_handler(Module, Options) ->
    gen_server:call(?MODULE, {add_handler, Module, Options}).

delete_packet_handler(Module) ->
    gen_server:call(?MODULE, {delete_handler, Module}).

apply_packet_handlers(SrcIP, Pdu, Handlers) ->
    lists:foreach(fun(Mod) -> Mod:handle_packet(SrcIP, Pdu) end, Handlers).

process_packet(<<9:16, _/binary>> = Packet, IP) ->
    netflow_v9:decode(Packet, IP);
process_packet(<<5:16, _/binary>> = Packet, _) ->
    netflow_v5:decode(Packet);
process_packet(_, _) ->
    {error, unknown_packet}.

process_listen_options(Options) ->
    case proplists:get_all_values(listen, Options) of
        [{Family, StrIP, Port}] ->
            {ok, IP} = inet_parse:address(StrIP),
            SocketOpts = [binary, Family, {ip, IP}, {active, true},
                {reuseaddr, true}],
            {ok, {StrIP, Port, SocketOpts}};
        _ ->
            {error, invalid_options}
    end.

init([Options]) ->
    case process_listen_options(Options) of
        {ok, {StrIP, Port, SocketOpts}} ->
            case gen_udp:open(Port, SocketOpts) of
                {ok, Socket} ->
                    ?INFO_MSG("Starting service ~p on ~s:~p~n", [?MODULE, StrIP, Port]),
                    netflow_v9:init(),
                    {ok, #state{socket = Socket, port = Port}};
                {error, Reason} ->
                    {stop, Reason}
            end;
        {error, Reason} ->
            ?ERROR_MSG("Invalid options for Netflow listener: ~p~n", [Options]),
            {stop, Reason}
    end.

handle_info({udp, _Socket, IP, _InPortNo, Packet}, State) ->
    case process_packet(Packet, IP) of
        {ok, Pdu} ->
            apply_packet_handlers(IP, Pdu, State#state.handlers),
            {noreply, State};
        {error, {badpdu, Reason}} ->
            ?INFO_MSG("Invalid packet has been discarded due ~p~n", [Reason]),
            {noreply, State};
        {error, Reason} ->
            ?INFO_MSG("Unable to process packet due ~p~n", [Reason]),
            {noreply, State}
    end.

handle_call({add_handler, Module, _Options}, _From, State) ->
    ?INFO_MSG("Registered packet handler: ~p~n", [Module]),
    Handlers = [Module | State#state.handlers],
    NewState = State#state{handlers = Handlers},
    {reply, ok, NewState};
handle_call({delete_handler, Module}, _From, State) ->
    ?INFO_MSG("Unregistering packet handler: ~p~n", [Module]),
    Handlers = lists:delete(Module, State#state.handlers),
    NewState = State#state{handlers = Handlers},
    {reply, ok, NewState};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, State) ->
    gen_udp:close(State#state.socket).
