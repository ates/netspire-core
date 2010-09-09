-module(netspire_radius).
-behaviour(supervisor).

%% API
-export([start/1, get_service_ref/1]).

%% supervisor callbacks
-export([start_link/0, init/1]).

-include("netspire.hrl").

start(Options) ->
    ChildSpec = {?MODULE,
                 {?MODULE, start_link, []},
                 permanent,
                 infinity,
                 supervisor,
                 [?MODULE]
                },
    supervisor:start_child(netspire_sup, ChildSpec),
    lists:map(fun process_option/1, Options).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    radius_dict:start(),
    {ok, {{one_for_one, 10, 1}, []}}.

process_option({listen, Options}) ->
    lists:foreach(fun process_listen_option/1, Options);
process_option({Ident, Options}) ->
    process_option({Ident, netspire_radius_h, Options});
process_option({Ident, Module, Options}) ->
    case code:ensure_loaded(Module) of
        {module, Module} ->
            Ref = get_service_ref(Ident),
            Clients = proplists:get_all_values(client, Options),
            Fun = fun(Client) -> add_request_handler(Ref, Module, Client) end,
            lists:foreach(Fun, Clients);
        _ ->
            ?ERROR_MSG("Radius handler module ~p is not found~n", [Module])
    end.

add_request_handler(Ref, Module, {Name, StrIP, Secret}) ->
    {ok, IP} = inet_parse:address(StrIP),
    Client = {Name, IP, Secret, Module},
    gen_radius:add_request_handler(Ref, Client).

process_listen_option({Ident, {Family, StrIP, Port}}) ->
    {ok, IP} = inet_parse:address(StrIP),
    Name = get_service_ref(Ident),
    ChildSpec = {
      Name,
      {gen_radius, start_link, [Name, Port, IP, Family]},
      permanent,
      brutal_kill,
      worker,
      [gen_radius]
     },
     supervisor:start_child(?MODULE, ChildSpec).

get_service_ref(Ident) ->
    list_to_atom("gen_radius_" ++ atom_to_list(Ident)).
