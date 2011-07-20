%%% Implementation of the Digest authentication protocol
%%% As defined in draft-sterman-aaa-sip-00.txt
%%% http://tools.ietf.org/id/draft-sterman-aaa-sip-01.txt
-module(mod_digest).

-behaviour(gen_module).

%% API
-export([verify_digest/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("../netspire.hrl").
-include("../radius/radius.hrl").

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    netspire_hooks:add(radius_auth, ?MODULE, verify_digest).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_digest).

verify_digest(_, Request, UserNameRealm, Password, Replies, _Client) ->
    case radius:attribute_value("Digest-Response", Request) of
        undefined -> Request;
        DigestResponse ->
            case radius:attribute_value("Digest-Attributes", Request) of
                undefined -> undefined;
                _Attrs ->
                    UserName = hd(string:tokens(UserNameRealm, "@")),
                    Nonce = attribute_value("Digest-Nonce", Request),
                    CNonce = attribute_value("Digest-CNonce", Request),
                    HA1 = do_ha1(UserName, Password, Nonce, CNonce, Request),
                    RespHash = do_digest(HA1, Nonce, CNonce, Request),
                    case RespHash == DigestResponse of
                        true ->
                            ?INFO_MSG("Digest authentication succeeded: ~p~n", [UserName]),
                            {stop, {accept, Replies}};
                        _ ->
                            ?INFO_MSG("Digest authentication failed: ~p~n", [UserName]),
                            {stop, {reject, []}}
                    end

            end
    end.

%%
%% Internal functions
%%
do_ha1(UserName, Password, Nonce, CNonce, Request) ->
    Realm = attribute_value("Digest-Realm", Request),
    Algorithm = attribute_value("Digest-Algorithm", Request),

    H = crypto:md5([UserName, ":", Realm, ":", Password]),
    HA = string:to_lower(netspire_util:binary_to_hex_string(H)),
    
    if
        Algorithm == <<"MD5-sess">> orelse Algorithm == <<"MD5-Sess">> ->
            Hash = crypto:md5([HA, ":", Nonce, ":", CNonce]),
            string:to_lower(netspire_util:binary_to_hex_string(Hash));
        true -> HA
    end.

do_digest(HA1, Nonce, CNonce, Request) ->
    Method = attribute_value("Digest-Method", Request),
    DigestURI = attribute_value("Digest-URI", Request),
    Qop = attribute_value("Digest-Qop", Request),
    NonceCount = attribute_value("Digest-Nonce-Count", Request),
    Entiny = attribute_value("Digest-Entity-Body-Hash", Request),

    HA2 = case Qop of
        <<"auth-int">> ->
            crypto:md5([Method, ":", DigestURI, ":", Entiny]);
        _ ->
            crypto:md5([Method, ":", DigestURI])
    end,
    HA2Hex = string:to_lower(netspire_util:binary_to_hex_string(HA2)),

    RespHash = case Qop of
        undefined ->
            crypto:md5([HA1, ":", Nonce, ":", HA2Hex]);
        _ ->
            crypto:md5([HA1, ":", Nonce, ":", NonceCount, ":", CNonce, ":", Qop, ":", HA2Hex])
    end,
    string:to_lower(netspire_util:binary_to_hex_string(RespHash)).

attribute_value(Name, Request) ->
    Attrs = Request#radius_packet.attrs,
    A = [parse_attribute(A) || A <- Attrs, A =/= undefined],
    proplists:get_value(Name, A).

parse_attribute({"Digest-Attributes", Value}) ->
    <<Code:8, Len:8, Attr/binary>> = Value,
    if
        Len < 3 orelse Len > byte_size(Value) ->
            ?WARNING_MSG("Invalid attribute length~n", []),
            undefined;
        true ->
            case Code of
                1 -> {"Digest-Realm", Attr};
                2 -> {"Digest-Nonce", Attr};
                3 -> {"Digest-Method", Attr};
                4 -> {"Digest-URI", Attr};
                5 -> {"Digest-Qop", Attr};
                6 -> {"Digest-Algorithm", Attr};
                7 -> {"Digest-Entity-Body-Hash", Attr};
                8 -> {"Digest-CNonce", Attr};
                9 -> {"Digest-Nonce-Count", Attr};
                10 -> {"Digest-Username", Attr}
            end
    end;
parse_attribute({_, _}) ->
    undefined.
