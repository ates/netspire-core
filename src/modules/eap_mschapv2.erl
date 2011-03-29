%%%
%%% draft-kamath-pppext-eap-mschapv2-00.txt
%%%
-module(eap_mschapv2).

-export([challenge/2, check_challenge/3]).

-include("eap.hrl").

-define(CODE_RESPONSE, 2).

-define(OPCODE_CHALLENGE, 1).
-define(OPCODE_RESPONSE, 2).
-define(OPCODE_SUCCESS, 3).
-define(OPCODE_FAILURE, 4).

-define(CHALLENGE_LEN, 16). % 16 octets

-define(SIZE, 26). % size of packet without NAME length
-define(NAME, "eap-mschapv2").

%% Challenge packet
%%
%%  0                   1                   2                   3
%%  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |     Code      |   Identifier  |            Length             |
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |     Type      |   OpCode      |  MS-CHAPv2-ID |  MS-Length...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |   MS-Length   |  Value-Size   |  Challenge...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |                             Challenge...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |                             Name...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

challenge(_Challenge, Ident) ->
    Challenge = libeap:make_challenge(),
    Length = ?SIZE + byte_size(<<?NAME>>),
    EAPMessage = list_to_binary([<<?EAP_REQUEST:8>>,            % Code, 1 octet
                                 <<(Ident + 1):8>>,             % Ident, 1 octet
                                 <<Length:16>>,                 % Length, 2 octets
                                 <<?EAP_MSCHAPV2_RESPONSE:8>>,  % Type, 1 octet
                                 <<?OPCODE_CHALLENGE:8>>,       % OpCode, 1 octet
                                 <<(Ident + 1):8>>,             % MS-CHAPv2-ID, 1 octet
                                 <<(Length - 5):16>>,           % MS-Length, 2 octets
                                 <<16:8>>,                      % Value-Size, 1 octet, value should be 16
                                 Challenge,                     % Challenge
                                 ?NAME]),
    [{"EAP-Message", EAPMessage}].

%% Response packet
%%
%% 0                   1                   2                   3
%% 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |     Code      |   Identifier  |            Length             |
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |     Type      |   OpCode      |  MS-CHAPv2-ID |  MS-Length...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |   MS-Length   |  Value-Size   |    Response...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |                             Response...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |                             Name...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
check_challenge(Value, Challenge, Password) ->
    io:format("Value: ~p~n", [Value]),
    io:format("EAP-MSCHAPv2 Dump:~n"),
    <<_:8, _:8, _:16, _:8, Data/binary>> = Value,
    <<OpCode:8, Ident:8, MSLen:16, ValueSize:8, Response:49/binary-unit:8, Name:4/binary-unit:8>> = Data,
    <<PeerChallenge:16/binary-unit:8, Zero:8/binary-unit:8, NTResponse:24/binary-unit:8, Flags:1/binary-unit:8>> = Response,
    io:format("OpCode: ~p~nMS-CHAPv2-ID: ~p~nMS-Length: ~p~nValue-Size: ~p~nResponse: ~p~nName: ~p~n", [OpCode, Ident, MSLen, ValueSize, Response, Name]),
    io:format("Response decode:~n"),
    io:format("Peer-Challenge: ~p~nZeros: ~p~nNT-Response: ~p~nFlags: ~p~n", [PeerChallenge, Zero, NTResponse, Flags]),
    io:format("Challenge: ~p~n", [Challenge]).

