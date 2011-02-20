-module(eap_md5).

-export([challenge/1, verify_md5/3]).

-include("eap.hrl").
-include("../netspire.hrl").

challenge(Packet) ->
    <<?EAP_PACKET>> = Packet,
    Challenge = make_challenge(),
    MD5Packet = list_to_binary([<<16:8>>, Challenge]),
    Len = 5 + byte_size(MD5Packet),
    % Request, Ident + 1, Len, MD5 Challenge, MD5 Packet
    Id = Ident + 1,
    EAPMessage = list_to_binary([<<1:8, Id:8, Len:16, 4:8>>, MD5Packet]),
    UserName = binary_to_list(Data),
    State = make_state(Data),
    R = #eap_client{username = UserName, data = Challenge, state = State},
    ets:insert(eap_client, R),
    [{"EAP-Message", EAPMessage}, {"State", State}].

verify_md5(Request, EAP, Password) ->
    {eap_client, UserName, Challenge, State} = EAP,
    State1 = radius:attribute_value("State", Request),
    EAPMessage = radius:attribute_value("EAP-Message", Request),
    case State =:= list_to_binary(State1) of
        false ->
            ?WARNING_MSG("State is not the same~n", []),
            {error, bad_state};
        true ->
            <<?EAP_PACKET>> = EAPMessage,
            Hash = crypto:md5([Ident, Password, Challenge]),
            <<_Size:8, ReqHash/binary>> = Data,
            case Hash =:= ReqHash of
                true ->
                    ets:delete(eap_client, UserName),
                    ok;
                false ->
                    ets:delete(eap_client, UserName),
                    {error, bad_md5_hash}
            end
    end.



make_challenge() ->
    random:seed(now()),
    R = lists:map(fun(_) -> random:uniform(255) end, lists:seq(1, random:uniform(255))),
    crypto:md5(R).

make_state(Data) ->
    TimeStamp = netspire_util:timestamp(),
    crypto:md5(list_to_binary([Data, <<TimeStamp>>])).

