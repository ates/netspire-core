%%% IP address's manipulation routines
-module(iplib).

-export([ip2long/1, long2ip/1, ipv4_to_ipv6/1, broadcast/1, number_of_hosts/1,
         range/1, range2list/1, in_range/2, is_ipv4_mapped/1,
         bin_ipv6_to_string/1, ipv6_to_binary/1, is_macaddr/1]).

-define(MAC_REGEXP, "^([0-9a-f]{2}([:-]|$)){6}$").

ip2long(IP) when is_integer(IP) -> IP;
ip2long(IP) when is_list(IP) ->
    case inet_parse:address(IP) of
        {ok, Address} -> ip2long(Address);
        Error -> Error
    end;
ip2long({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
ip2long({W7, W6, W5, W4, W3, W2, W1, W0}) ->
    (W7 bsl 112) bor (W6 bsl 96) bor (W5 bsl 80) bor (W4 bsl 64) bor (W3 bsl 48) bor (W2 bsl 32) bor (W1 bsl 16) bor W0.

% Limitation: support only IPv4
long2ip(IP) when IP =< 4294967295 ->
    {(IP div 16777216) rem 256, (IP div 65536) rem 256, (IP div 256) rem 256, IP rem 256}.

ipv4_to_ipv6(Address) when is_list(Address) ->
    {ok, {A, B, C, D}} = inet_parse:address(Address),
    ipv4_to_ipv6({A, B, C, D});
ipv4_to_ipv6({A, B, C, D}) ->
    IP = {0, 0, 0, 0, 0, 16#ffff, (A bsl 8) bor B, (C bsl 8) bor D},
    inet_parse:ntoa(IP).

is_ipv4_mapped(Address) ->
    (ip2long(Address) bsr 32) =:= 16#ffff.

broadcast(Address) ->
    {IP, Mask} = parse_address(Address),
    Network = ip2long(IP) band ip2long(Mask),
    long2ip(Network bor (bnot ip2long(Mask) band 16#ffffffff)).

number_of_hosts(Address) ->
    Broadcast = ip2long(broadcast(Address)),
    {IP, Mask} = parse_address(Address),
    Broadcast - (ip2long(IP) band Mask) - 1.

range(Address) ->
    Broadcast = ip2long(broadcast(Address)),
    {IP, Mask} = parse_address(Address),
    case Mask of
        4294967294 -> % 31
            {long2ip((ip2long(IP) band ip2long(Mask))), long2ip(Broadcast)};
        4294967295 -> % 32
            {long2ip(ip2long(IP)), long2ip(ip2long(IP))};
        _ ->
            {long2ip((ip2long(IP) band ip2long(Mask)) + 1), long2ip(Broadcast - 1)}
    end.

range2list(Address) when is_list(Address) ->
    case string:tokens(Address, "-") of
        [First, Last] ->
            try
                {ok, {I1, I2, I3, I4}} = inet_parse:address(First),
                {ok, {I5, I6, I7, I8}} = inet_parse:address(Last),
                {I1, I2, I3} = {I5, I6, I7},
                [{I1, I2, I3, I} || I <- lists:seq(I4, I8)]
            catch
                _:_ -> []
            end;
        _ ->
            {F, L} = range(Address),
            [long2ip(I) || I <- lists:seq(ip2long(F), ip2long(L))]
    end.

in_range(Address, N) ->
    {Network, Mask} = parse_address(N),
    (ip2long(Address) band Mask) == (ip2long(Network) band Mask).

bin_ipv6_to_string(Bin) when byte_size(Bin) =:= 16 ->
    List = bin_ipv6_to_string([erlang:integer_to_list(I, 16) || <<I:4>> <= Bin]),
    string:join(List, ":");
bin_ipv6_to_string([]) -> [];
bin_ipv6_to_string([A, B, C, D | Rest] = List) when is_list(List) ->
   [lists:flatten([A, B, C, D])] ++ bin_ipv6_to_string(Rest).

ipv6_to_binary(List) when is_list(List) ->
    case string:chr(List, $:) of
        0 ->
            <<<<(erlang:list_to_integer([H], 16)):4>> || H <- List>>;
        _ ->
            FlatList = lists:flatten(string:tokens(List, ":")),
            <<<<(erlang:list_to_integer([H], 16)):4>> || H <- FlatList>>
    end.

% verify mac address syntax, : or - may be used as delimiter
is_macaddr(Address) ->
    case re:run(Address, ?MAC_REGEXP, [{capture, none}, caseless]) of
        match -> true;
        _ -> false
    end.

%%
%% Internal functions
%%
parse_address(Address) ->
    case string:tokens(Address, "/") of
        [IP, M] ->
            try
                Mask = list_to_integer(M),
                {IP, (16#ffffffff bsr (32 - Mask)) bsl (32 - Mask)}
            catch
                _:_ -> {IP, ip2long(M)}
            end;
        _ ->
            % assume that Address specified without / and assign 32 as mask
            {Address, ip2long("255.255.255.255")}
    end.
