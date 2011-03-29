-module(mod_eap).

-behaviour(gen_module).

%% API
-export([verify_eap/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("eap.hrl").
-include("../netspire.hrl").
-include("../radius/radius.hrl").

-define(EAP_STATE, eap_state).

%% Used to store previous EAP requests
-record(eap_state, {username, state, pid}).

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    ets:new(?EAP_STATE, [public, named_table, {keypos, 2}]),
    netspire_hooks:add(radius_auth, ?MODULE, verify_eap).

stop() ->
    ?INFO_MSG("Stop dynamic module ~p~n", [?MODULE]),
    ets:delete(?EAP_STATE),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_eap).

verify_eap(_, Request, UserName, Password, Replies, _Client) ->
    case libeap:attribute_value(Request) of
        undefined -> undefined;
        Value ->
            State = radius:attribute_value("State", Request),
            dump_eap_message(Value),
            <<_Code:8, Ident:8, _Len:16, Type:8, Data/binary>> = Value,
            case Type of
                ?EAP_IDENTIFY -> % Identify. Send EAP-MD5 Challenge
                    {ok, Pid} = eap_md5:start_link(),
                    NewState = libeap:make_state(Data),
                    EAPMessage = gen_fsm:sync_send_event(Pid, {challenge, Value}),
                    update_eap_state(UserName, NewState, Pid),
                    Attrs = EAPMessage ++ [{"State", NewState}],
                    {stop, {challenge, Attrs}};
                ?EAP_NAK -> % NAK
                    <<AuthType:8>> = Data,
                    case AuthType of
                        ?EAP_MSCHAPV2 -> % send MSCHAPv2 Challenge
                            Challenge = libeap:make_challenge(),
                            EAPMessage = eap_mschapv2:challenge(Challenge, Ident),
                            {stop, {challenge, EAPMessage}};
                        _ ->
                            ?INFO_MSG("Auth type ~p not implemented~n", [AuthType]),
                            {stop, {reject, []}}
                    end;
                ?EAP_MD5_CHALLENGE -> % Perform EAP-MD5 verification
                    case fetch_eap_state(UserName, State) of
                        undefined ->
                            ?INFO_MSG("No found EAP state for ~s user. Discarding request~n", [UserName]),
                            {stop, {reject, libeap:eap_failure(Ident)}};
                        S when is_record(S, eap_state) ->
                            delete_eap_state(UserName),
                            case gen_fsm:sync_send_event(S#eap_state.pid, {verify, Ident, Data, Password}) of
                                true ->
                                    {stop, {accept, libeap:eap_success(Ident) ++ Replies}};
                                _ ->
                                    ?INFO_MSG("EAP-MD5 verification for user ~s failed~n", [UserName]),
                                    {stop, {reject, libeap:eap_failure(Ident)}}
                            end
                    end;
                ?EAP_MSCHAPV2 ->
%                    S = fetch_eap_state(UserName, State),
%                    eap_mschapv2:check_challenge(Value, S#eap_state.data, Password),
                    io:format("Need to check prev challeg~n"),
                    {stop, {reject, []}}
            end
    end.

update_eap_state(UserName, State, Pid) ->
    R = #eap_state{username = UserName, state = State, pid = Pid},
    ets:insert(eap_state, R).

delete_eap_state(UserName) ->
    ets:delete(eap_state, UserName).

fetch_eap_state(UserName, S) ->
    case ets:lookup(eap_state, UserName) of
        [State] ->
            case State#eap_state.state =:= S of
                true -> State;
                false -> undefined
            end;
        _ -> undefined
    end.

detect_auth_type(Code, Ident) ->
    case Code of
        ?EAP_TLS ->
            io:format("TLS auth type not implemented~n"),
            {stop, {reject, []}};
        ?EAP_LEAP ->
            io:format("LEAP auth type not implemented~n"),
            {stop, {reject, []}};
        ?EAP_TTLS ->
            io:format("TTLS auth type not implemented~n"),
            {stop, {reject, []}};
        ?EAP_PEAP ->
            io:format("PEAP auth type not implemented~n"),
            {stop, {reject, []}};
        ?EAP_MSCHAPV2 -> % MS CHAP v2
            Challenge = libeap:make_challenge(),
            EAPMessage = eap_mschapv2:challenge(Challenge, Ident),
            {stop, {challenge, EAPMessage}};
        _ ->
            ?INFO_MSG("Unsupported authentication type~n", []),
            {stop, {reject, []}}
    end.

%%% TESTING

eap_message_code_to_string(1) ->
    "Request";
eap_message_code_to_string(2) ->
    "Response";
eap_message_code_to_string(3) ->
    "Success";
eap_message_code_to_string(4) ->
    "Failure".

eap_message_type_to_string(1) ->
    "Identity";
eap_message_type_to_string(2) ->
    "Notification";
eap_message_type_to_string(3) ->
    "Nak (Response only)";
eap_message_type_to_string(4) ->
    "MD5-Challenge";
eap_message_type_to_string(5) ->
    "One-Time Password (OTP) (RFC 1938)";
eap_message_type_to_string(6) ->
    "Generic Token Card";
eap_message_type_to_string(_) ->
    "Unknown Type".

eap_nak_type_to_string(13) ->
    "TLS";
eap_nak_type_to_string(17) ->
    "LEAP";
eap_nak_type_to_string(18) ->
    "SIM";
eap_nak_type_to_string(21) ->
    "TTLS";
eap_nak_type_to_string(25) ->
    "PEAP";
eap_nak_type_to_string(26) ->
    "MSCHAPv2";
eap_nak_type_to_string(29) ->
    "Cisco MSCHAPv2";
eap_nak_type_to_string(Code) ->
    io:format("unknown type: ~p~n", [Code]),
    unknown.

dump_eap_message(Value) ->
    <<?EAP_PACKET>> = Value,
    io:format("EAP-Message packet dump:~n", []),
    io:format("Code: ~p (~s)~n", [Code, eap_message_code_to_string(Code)]),
    io:format("Id: ~p~n", [Ident]),
    io:format("Length: ~p~n", [Length]),
    io:format("Type: ~p: ~s~n", [Type, eap_message_type_to_string(Type)]),
    case Type of
        3 ->
            <<T:8>> = Data,
            io:format("Auth type: ~p~n", [eap_nak_type_to_string(T)]);
        _ ->
            io:format("Data: ~p~n", [Data])
    end,
    io:format("---------------------------------~n").
