-module(mod_eap).

-behaviour(gen_module).

%% API
-export([verify_eap/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("eap.hrl").
-include("../netspire.hrl").
-include("../radius/radius.hrl").

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    ets:new(eap_client, [public, named_table, {keypos, 2}]),
    netspire_hooks:add(radius_auth, ?MODULE, verify_eap).

stop() ->
    ?INFO_MSG("Stop dynamic module ~p~n", [?MODULE]),
    ets:delete(eap_client),
    netspire_hooks:delete(radius_auth, ?MODULE, verify_eap).

verify_eap(_, Request, UserName, Password, Replies, _Client) ->
    case radius:attribute_value("EAP-Message", Request) of
        undefined -> undefined;
        Value ->
            %dump_eap_message(Value),
            case radius:attribute_value("Message-Authenticator", Request) of
                undefined -> undefined;
                _MA ->
				    case ets:lookup(eap_client, UserName) of
				        [EAP] ->
                            <<?EAP_PACKET>> = Value,
                            case eap_md5:verify_md5(Request, EAP, Password) of
                                ok ->
                                    % EAP Success, Failure
                                    % Codes: 3 - Success, 4 - Failure
                                    % Ident: Take Ident from Request packet
                                    % Size: Always 4 bytes
                                    % <<Code:8, Ident:8, Size:16>>
                                    S = [{"EAP-Message", <<3:8, Ident:8, 4:16>>}],  % EAP Success packet
                                    {stop, {accept, S ++ Replies}};
                                _ ->
                                    F = [{"EAP-Message", <<4:8, Ident:8, 4:16>>}],  % EAP Failure packet
                                    {reject, [F]}
                            end;
                        [] ->
                            Attrs = eap_md5:challenge(Value),
		                    {stop, {challenge, Attrs}}
				    end
            end
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
    "Generic Token Card".

dump_eap_message(Value) ->
    <<?EAP_PACKET>> = Value,
    io:format("EAP-Message packet dump:~n", []),
    io:format("Code: ~p (~s)~n", [Code, eap_message_code_to_string(Code)]),
    io:format("Id: ~p~n", [Ident]),
    io:format("Length: ~p~n", [Length]),
    io:format("Type: ~p: ~s~n", [Type, eap_message_type_to_string(Type)]),
    io:format("Data: ~p~n", [Data]).

