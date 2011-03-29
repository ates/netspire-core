-module(libeap).

-export([make_challenge/0, make_state/1, eap_success/1, eap_failure/1, attribute_value/1]).

-include("eap.hrl").
-include("../radius/radius.hrl").

%% Generate MD5 hash using random list
make_challenge() ->
    random:seed(now()),
    R = lists:map(fun(_) -> random:uniform(255) end, lists:seq(1, random:uniform(255))),
    crypto:md5(R).

%% Returns uniq State
make_state(Data) ->
    TimeStamp = netspire_util:timestamp(),
    binary_to_list(crypto:md5([Data, <<TimeStamp>>])).

%% EAP Success and Failure packet format
%% 
%% 0                   1                   2                   3
%% 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |     Code      |  Identifier   |            Length             |
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%
%% Length is 4 octets

%% Returns Success or Failure EAP packet
eap_success(Ident) ->
    [{"EAP-Message", <<?EAP_SUCCESS:8, Ident:8, 4:16>>}].
eap_failure(Ident) ->
    [{"EAP-Message", <<?EAP_FAILURE:8, Ident:8, 4:16>>}].

attribute_value(Request) ->
    Attrs = Request#radius_packet.attrs,
    case proplists:get_all_values("EAP-Message", Attrs) of
        [] -> undefined;
        List -> list_to_binary(List)
    end.

