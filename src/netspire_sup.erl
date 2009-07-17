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
    CryptoSup = {netspire_crypto_sup,
                 {netspire_crypto_sup, start_link, []},
                 permanent,
                 infinity,
                 supervisor,
                 [netspire_crypto_sup]
                },
    {ok, {{one_for_one, 10, 1}, [Hooks, CryptoSup]}}.
