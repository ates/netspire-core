-module(netspire_crypto_sup).

-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    CryptoSrv = {
        netspire_crypto_srv,
        {netspire_crypto_srv, start_link, []},
        permanent,
        2000,
        worker,
        [netspire_crypto_srv]
    },
    
    {ok, {{one_for_all, 10, 3600}, [CryptoSrv]}}.
