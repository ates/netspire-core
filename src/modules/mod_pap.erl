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
    ?INFO_MSG("Stop dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_pap).

verify_pap(_, Request, UserName, Password, Replies, Client) ->
    case radius:attribute_value("Password", Request) of
        undefined ->
            Request;
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
    PX = do_bxor(P, erlang:md5([Secret, Auth])),
    pap_encrypt_password(Rest, Secret, PX, concat_binary([Ret, PX]));
pap_encrypt_password(P, Secret, Auth, Ret) ->
    PX = do_bxor(P, erlang:md5([Secret, Auth])),
    binary_to_list(concat_binary([Ret, PX])).

do_bxor(B1, B2) ->
    do_bxor(B1, B2, <<>>).
do_bxor(<<>>, B2, Ret) ->
    concat_binary([Ret, B2]);
do_bxor(<<I1, Rest1/binary>>, <<I2, Rest2/binary>>, Acc) ->
    do_bxor(Rest1, Rest2, concat_binary([Acc, I1 bxor I2])).

