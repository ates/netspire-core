-module(mod_eap_md5).

-behaviuor(gen_module).

%% API
-export([verify_eap/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("eap.hrl").
-include("../netspire.hrl").
-include("../radius/radius.hrl").

-define(CHALLENGE_LEN, 16).

-record(eap_md5_state, {username, challenge, state}).

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    ets:new(eap_md5_state, [named_table, public, {keypos, 2}]),
    netspire_hooks:add(radius_auth, ?MODULE, verify_eap).

stop() ->
    ?INFO_MSG("Stop dynamic module ~p~n", [?MODULE]),
    ets:delete(eap_md5_state),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_eap).

verify_eap(_, Request, UserName, Password, Replies, _Client) ->
    case libeap:attribute_value(Request) of
        undefined ->
            undefined;
        Value ->
            <<_Code:8, Ident:8, _Len:16, Type:8, Data/binary>> = Value,
            case Type of
                ?EAP_IDENTIFY -> % Send EAP-MD5 Challenge
                    Challenge = libeap:make_challenge(),
                    State = libeap:make_state(Data),
                    MD5Packet = list_to_binary([<<?CHALLENGE_LEN:8>>, Challenge]),
                    Length = 5 + byte_size(MD5Packet),
                    EAPMessage = list_to_binary([<<?EAP_REQUEST:8, (Ident + 1):8, Length:16, ?EAP_MD5_CHALLENGE:8>>, MD5Packet]),
                    ets:insert(eap_md5_state, #eap_md5_state{username = UserName, challenge = Challenge, state = State}),
                    Attrs = [{"EAP-Message", EAPMessage}, {"State", State}],
                    {stop, {challenge, Attrs}};
                ?EAP_MD5_CHALLENGE -> % Perform EAP-MD5 verification
                    State = radius:attribute_value("State", Request),
                    case find_request(UserName, State) of
                        undefined ->
                            ?INFO_MSG("Not found State attribute in request from ~s user~n", [UserName]),
                            {stop, {reject, libeap:eap_failure(Ident)}};
                        Session ->
                            ets:delete(eap_md5_state, UserName),
                            do_eap_md5(Ident, UserName, Password, Session#eap_md5_state.challenge, Replies, Data)
                    end;
                _ ->
                    ?WARNING_MSG("Unknown EAP Message type received from ~s user. "
                        "Discarding packet~n", [UserName]),
                    {stop, {reject, []}}
            end
    end.

%%
%% Internal functions
%%
do_eap_md5(Ident, UserName, Password, Challenge, Replies, Data) ->
    Hash = crypto:md5([Ident, Password, Challenge]),
    <<_Size:8, ReqHash:16/binary-unit:8, _Rest/binary>> = Data,
    case Hash =:= ReqHash of
        true ->
            ?INFO_MSG("EAP-MD5 authentication succeeded: ~p~n", [UserName]),
            {stop, {accept, libeap:eap_success(Ident) ++ Replies}};
        _ ->
            ?INFO_MSG("EAP-MD5 authentication failed: ~p~n", [UserName]),
            {stop, {reject, libeap:eap_failure(Ident)}}
    end.

find_request(UserName, S) ->
    case ets:lookup(eap_md5_state, UserName) of
        [State] when State#eap_md5_state.state =:= S -> State;
        _ ->
            undefined
    end.
