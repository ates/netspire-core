-module(radclient).

-export([request/3]).

-include("radius.hrl").
-include("../netspire.hrl").

-define(TRIES, 3).
-define(TIMEOUT, 2000). % 2 seconds
-define(ACCESS_REQUEST_PORT, 1812).
-define(ACCOUNTING_REQUEST_PORT, 1813).
-define(POD_COA_REQUEST_PORT, 3799).

request(Type, NasSpec, Attrs) ->
    {nas_spec, IP, _, Secret, _} = NasSpec,
    request(Type, IP, Secret, Attrs).

%%
%% Internal functions
%%
request(auth, IP, Secret, Attrs) ->
    Packet = generate_packet(?ACCESS_REQUEST, Secret, Attrs),
    case send_packet(IP, ?ACCESS_REQUEST_PORT, Packet, ?TRIES) of
        {ok, Reply} ->
            case Reply#radius_packet.code of
                ?ACCESS_ACCEPT ->
                    {accept, Reply#radius_packet.attrs};
                _ ->
                    {reject, Reply#radius_packet.attrs}
            end;
        Error -> Error
    end;
request(acct, IP, Secret, Attrs) ->
    Packet = generate_packet(?ACCOUNTING_REQUEST, Secret, Attrs),
    case send_packet(IP, ?ACCOUNTING_REQUEST_PORT, Packet, ?TRIES) of
        {ok, Reply} when Reply#radius_packet.code == ?ACCT_RESPONSE -> ok;
        _ -> noreply
    end;
request(disconnect, IP, Secret, Attrs) ->
    Packet = generate_packet(?DISCONNECT_REQUEST, Secret, Attrs),
    case send_packet(IP, ?POD_COA_REQUEST_PORT, Packet, ?TRIES) of
        {ok, Reply} ->
            case Reply#radius_packet.code of
                ?DISCONNECT_ACK -> {ok, Reply#radius_packet.attrs};
                ?DISCONNECT_NAK -> {error, Reply#radius_packet.attrs}
            end;
        Error -> Error
    end;
request(coa, IP, Secret, Attrs) ->
    Packet = generate_packet(?COA_REQUEST, Secret, Attrs),
    case send_packet(IP, ?POD_COA_REQUEST_PORT, Packet, ?TRIES) of
        {ok, Reply} ->
            case Reply#radius_packet.code of
                ?COA_ACK -> {ok, Reply#radius_packet.attrs};
                ?COA_NAK -> {error, Reply#radius_packet.attrs}
            end;
        Error -> Error
    end.

send_packet(_IP, _Port, _Packet, 0) ->
    {error, timeout};
send_packet(IP, Port, Packet, Tries) ->
    case gen_udp:open(0, [binary]) of
        {ok, Socket} ->
            gen_udp:send(Socket, IP, Port, Packet),
            case waiting_for_reply() of
                {ok, Reply} ->
                    {ok, Reply};
                {error, timeout} ->
                     send_packet(IP, Port, Packet, Tries - 1)
            end;
        {error, Reason} ->
            ?ERROR_MSG("Cannot open socket due to ~p~n", [Reason])
    end.

waiting_for_reply() ->
    receive
        {udp, Socket, _IP, _InPortNo, Bin} ->
            gen_udp:close(Socket),
            case radius:decode_packet(Bin, "") of
                {ok, Packet} ->
                    {ok, Packet};
                {error, Reason} ->
                    ?ERROR_MSG("Cannot decode packet due to ~p~n", [Reason]),
                    {error, Reason}
            end
    after ?TIMEOUT ->
        {error, timeout}
end.

generate_packet(RequestId, Secret, Attrs) ->
    random:seed(now()),
    Ident = random:uniform(255),
    Code = <<RequestId:8>>,
    {ok, A} = radius:encode_attributes(Attrs),
    Length = <<(20 + byte_size(A)):16>>,
    Auth = crypto:md5([Code, Ident, Length, <<0:128>>, A, Secret]),
    [Code, Ident, Length, Auth, A].

