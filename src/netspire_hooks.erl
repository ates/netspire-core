-module(netspire_hooks).

-behaviour(gen_server).

%% API
-export([start_link/0,
         add/3,
         add/4,
         delete/3,
         delete/4,
         run/2,
         run_fold/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-include("netspire.hrl").

-record(state, {}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

add(Hook, Module, Fun) ->
    add(Hook, Module, Fun, 100).
add(Hook, Module, Fun, Seq) ->
    gen_server:call(?MODULE, {add, Hook, Module, Fun, Seq}).

delete(Hook, Module, Fun) ->
    delete(Hook, Module, Fun, 100).
delete(Hook, Module, Fun, Seq) ->
    gen_server:call(?MODULE, {delete, Hook, Module, Fun, Seq}).

run(Hook, Args) ->
    case ets:lookup(hooks, Hook) of
        [{_, Ls}] ->
            do_run(Ls, Hook, Args);
        [] ->
            ok
    end.

run_fold(Hook, Val, Args) ->
    case ets:lookup(hooks, Hook) of
        [{_, Ls}] ->
            do_run_fold(Ls, Hook, Val, Args);
        [] ->
            Val
    end.

init([]) ->
    ets:new(hooks, [named_table]),
    {ok, #state{}}.

handle_call({add, Hook, Module, Fun, Seq}, _From, State) ->
    Reply = case ets:lookup(hooks, Hook) of
                [{_, Ls}] ->
                    El = {Seq, Module, Fun},
                    case lists:member(El, Ls) of
                        true ->
                            ok;
                        false ->
                            NewLs = lists:merge(Ls, [El]),
                            ets:insert(hooks, {Hook, NewLs}),
                            ok
                    end;
                [] ->
                    NewLs = [{Seq, Module, Fun}],
                    ets:insert(hooks, {Hook, NewLs}),
                    ok
            end,
    {reply, Reply, State};
handle_call({delete, Hook, Module, Fun, Seq}, _From, State) ->
    Reply = case ets:lookup(hooks, Hook) of
                [{_, Ls}] ->
                    NewLs = lists:delete({Seq, Module, Fun}, Ls),
                    ets:insert(hooks, {Hook, NewLs}),
                    ok;
                [] ->
                    ok
            end,
    {reply, Reply, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

do_run([], _Hook, _Args) ->
    ok;
do_run([{_Seq, Module, Fun} | Ls], Hook, Args) ->
    try apply(Module, Fun, Args) of
        stop ->
            ok;
        _ ->
            do_run(Ls, Hook, Args)
    catch
        _:Reason ->
            ?ERROR_MSG("Error while running hook ~p ~p"
                       " with args: ~p due ~p~n", [Hook, {Module, Fun}, Args, Reason]),
            do_run(Ls, Hook, Args)
    end.

do_run_fold([], _Hook, Value, _Args) ->
    Value;
do_run_fold([{_Seq, Module, Fun} | Ls], Hook, Value, Args) ->
    try apply(Module, Fun, [Value | Args]) of
        stop ->
            stop;
        {stop, NewValue} ->
            NewValue;
        NewValue ->
            do_run_fold(Ls, Hook, NewValue, Args)
    catch
        _:Reason ->
            ?ERROR_MSG("Error while running hook ~p ~p"
                       " with args: ~p due ~p~n", [Hook, {Module, Fun}, Args, Reason]),
            do_run_fold(Ls, Hook, Value, Args)
    end.
