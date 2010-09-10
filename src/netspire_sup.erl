-module(netspire_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Hooks = {netspire_hooks,
             {netspire_hooks, start_link, []},
             permanent,
             brutal_kill,
             worker,
             [netspire_hooks]
            },
    {ok, {{one_for_one, 10, 1}, [Hooks]}}.
