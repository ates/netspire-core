-module(netspire_util).

-export([timestamp/0, to_hex/1, do_bxor/2, binary_to_hex_string/1,
         normalize_ip/1]).

timestamp() ->
    {MegaSecs, Secs, _} = erlang:now(),
    MegaSecs * 1000000 + Secs.

to_hex(N) when N < 256 ->
    [hex(N div 16), hex(N rem 16)].

do_bxor(B1, B2) ->
    do_bxor(B1, B2, <<>>).
do_bxor(<<>>, B2, Ret) ->
    list_to_binary([Ret, B2]);
do_bxor(<<I1, Rest1/binary>>, <<I2, Rest2/binary>>, Acc) ->
    do_bxor(Rest1, Rest2, list_to_binary([Acc, I1 bxor I2])).

binary_to_hex_string(Bin) ->
    list_to_hex_string(binary_to_list(Bin)).

%% Returns family and ip_address()
normalize_ip(IP) when is_list(IP) ->
    case inet_parse:address(IP) of
        {ok, Address} ->
            normalize_ip(Address);
        _ ->
            {error, einval}
    end;
normalize_ip(IP) when tuple_size(IP) == 4 ->
    {ok, {inet, IP}};
normalize_ip(IP) when tuple_size(IP) == 8 ->
    {ok, {inet6, IP}}.

%% Internal functions
hex(N) when N < 10 ->
    $0 + N;
hex(N) when N >= 10, N < 16 ->
    $A + (N - 10).

list_to_hex_string([]) ->
    [];
list_to_hex_string([H | T]) ->
    to_hex(H) ++ list_to_hex_string(T).
