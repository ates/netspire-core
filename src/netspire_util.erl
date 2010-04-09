-module(netspire_util).

-export([ipconv/1, timestamp/0, to_hex/1, do_bxor/2, binary_to_hex_string/1]).

ipconv({A, B, C, D}) ->
    <<I:4/big-integer-unit:8>> = <<A, B, C, D>>, I;

ipconv(Bin) when is_binary(Bin) andalso size(Bin) == 16 ->
    Result = string:join(normalizev6(Bin), ":"),
    string:to_lower(Result);

ipconv(I) when is_integer(I) ->
    A = (I div 16777216) rem 256,
    B = (I div 65536) rem 256,
    C = (I div 256) rem 256,
    D = I rem 256,
    {A, B, C, D};

ipconv(IP) when is_list(IP) ->
    case inet_parse:address(IP) of
        {ok, Address} -> ipconv(Address);
        Error -> Error
    end.

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

%% Internal functions
hex(N) when N < 10 ->
    $0 + N;
hex(N) when N >= 10, N < 16 ->
    $A + (N - 10).

normalizev6(<<>>) ->
    [];
normalizev6(<<A:8, B:8, Rest/binary>>) ->
    [to_hex(A) ++ to_hex(B)] ++ normalizev6(Rest).

list_to_hex_string([]) ->
    [];
list_to_hex_string([H | T]) ->
    to_hex(H) ++ list_to_hex_string(T).
