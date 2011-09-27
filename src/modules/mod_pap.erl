-module(mod_pap).

-behaviour(gen_module).

%% API
-export([verify_pap/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("../netspire.hrl").
-include("../radius/radius.hrl").

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    netspire_hooks:add(radius_auth, ?MODULE, verify_pap).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_pap).

verify_pap(_, Request, UserName, Password, Replies, Client) ->
    case radius:attribute_value("User-Password", Request) of
        undefined -> undefined;
        UserPassword ->
            Secret = Client#nas_spec.secret,
            Auth = Request#radius_packet.auth,
            do_pap(UserName, UserPassword, Password, Secret, Auth, Replies)
    end.

do_pap(UserName, UserPassword, Password, Secret, Auth, Replies) ->
    PasswordHash = pap_encrypt_password(Password, Secret, Auth),
    case PasswordHash == UserPassword of
        true ->
            ?INFO_MSG("PAP authentication succeeded: ~p~n", [UserName]),
            {stop, {accept, Replies}};
        _ ->
            ?INFO_MSG("PAP authentication failed: ~p~n", [UserName]),
            {stop, {reject, []}}
    end.

pap_encrypt_password(P, Secret, Auth) ->
    pap_encrypt_password(list_to_binary(P), Secret, Auth, <<>>).

pap_encrypt_password(<<>>, _Secret, _Auth, Ret) ->
    binary_to_list(Ret);

pap_encrypt_password(<<P:16/binary, Rest/binary>>, Secret, Auth, Ret) ->
    PX = netspire_util:do_bxor(P, crypto:md5([Secret, Auth])),
    pap_encrypt_password(Rest, Secret, PX, list_to_binary([Ret, PX]));
pap_encrypt_password(P, Secret, Auth, Ret) ->
    PX = netspire_util:do_bxor(P, crypto:md5([Secret, Auth])),
    binary_to_list(list_to_binary([Ret, PX])).

