-module(netspire_crypto_srv).

-behaviour(gen_server).

-export([start_link/0, client_port/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    process_flag(trap_exit, true),
    erl_ddll:start(),
    PrivDir =
        case code:priv_dir(netspire) of
            {error, bad_name} ->
	            "./priv";
            D ->
                D
        end,

    LibDir = filename:join([PrivDir, "lib"]),
    case erl_ddll:load_driver(LibDir, netspire_crypto_drv) of
        ok ->
            ok;
        {error, _Reason} ->
            LibDir1 = filename:join(LibDir, erlang:system_info(system_architecture)),
            erl_ddll:load_driver(LibDir1, netspire_crypto_drv)
    end,
    Cmd = "netspire_crypto_drv",
    open_ports(Cmd, size(port_names())).

open_ports(_, 0) ->
    {ok, []};

open_ports(Cmd, N) ->
    Port = open_port({spawn, Cmd}, []),
    try
        port_control(Port, 0, []),
        register(element(N, port_names()), Port),
        open_ports(Cmd, N-1)
    catch
        error:_ ->
            {stop, nodriver}
    end.

port_names() ->
    {netspire_crypto_drv01, netspire_crypto_drv02, netspire_crypto_drv03,
     netspire_crypto_drv04, netspire_crypto_drv05, netspire_crypto_drv06,
     netspire_crypto_drv07, netspire_crypto_drv08, netspire_crypto_drv09,
     netspire_crypto_drv10, netspire_crypto_drv11, netspire_crypto_drv12,
     netspire_crypto_drv13, netspire_crypto_drv14, netspire_crypto_drv15,
     netspire_crypto_drv16}.

client_port() ->
    element(erlang:system_info(scheduler_id) rem size(port_names()) + 1, port_names()).

handle_call(_, _, State) ->
    {noreply, State}.

handle_cast(_, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, _Reason}, State) when is_pid(Pid) ->
    {noreply, State};

handle_info({'EXIT', Port, Reason}, State) when is_port(Port) ->
    {stop, {port_died, Reason}, State};

handle_info(_, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    close_ports(size(port_names())).

close_ports(0) ->
    ok;

close_ports(N) ->
    element(N, port_names()) ! {self(), close},
    close_ports(N - 1).
