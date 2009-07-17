-module(netspire_util).
-export([ip4_to_int/1, int_to_ip4/1]).

ip4_to_int({I1, I2, I3, I4}) ->
    <<I:4/big-integer-unit:8>> = <<I1, I2, I3, I4>>,
    I;

ip4_to_int(IP) ->
    {ok, {A, B, C, D}} = inet_parse:ipv4_address(IP),
    ip4_to_int({A, B, C, D}).

int_to_ip4(Int) ->
    A = (Int div 16777216) rem 256,
    B = (Int div 65536) rem 256,
    C = (Int div 256) rem 256,
    D = Int rem 256,
    {A, B, C, D}.
