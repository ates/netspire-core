%%% IP address's manipulation routines
-module(ip).

-export([ip2long/1, long2ip/1, ipv4_to_ipv6/1, broadcast/1, number_of_hosts/1,
         range/1, range2list/1, in_range/2, is_ipv4_mapped/1,
         bin_ipv6_to_string/1, ipv6_to_binary/1]).

-include_lib("eunit/include/eunit.hrl").

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
long2ip(IP) when is_integer(IP) andalso IP =< 4294967295 ->
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
                lists:map(fun(I) -> {I1, I2, I3, I} end, lists:seq(I4, I8))
            catch
                _:_ -> []
            end;
        _ ->
            {F, L} = range(Address),
            lists:map(fun(I) -> long2ip(I) end, lists:seq(ip2long(F), ip2long(L)))
    end.

in_range(Address, N) ->
    {Network, Mask} = parse_address(N),
    (ip2long(Address) band Mask) == (ip2long(Network) band Mask).

bin_ipv6_to_string(Bin) when is_binary(Bin) andalso size(Bin) == 16 ->
    List = bin_ipv6_to_string([integer_to_list(I, 16) || <<I:4>> <= Bin]),
    string:join(List, ":");
bin_ipv6_to_string([]) -> [];
bin_ipv6_to_string([A, B, C, D | Rest] = List) when is_list(List) ->
   [lists:flatten([A, B, C, D])] ++ bin_ipv6_to_string(Rest).

ipv6_to_binary(List) when is_list(List) ->
    case string:chr(List, $:) of
        0 ->
            <<<<(list_to_integer([H], 16)):4>> || H <- List>>;
        _ ->
            FlatList = lists:flatten(string:tokens(List, ":")),
            <<<<(list_to_integer([H], 16)):4>> || H <- FlatList>>
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

%%
%% Tests
%%
ip2long_test() ->
    ?assert(ip2long("192.168.10.1") =:= 3232238081),
    ?assert(ip2long({192, 168, 10, 1}) =:= 3232238081),
    ?assert(ip2long(3232238081) =:= 3232238081),
    ?assert(ip2long("dead:beaf::") =:= 295990749943530982778020572095127224320),
    ?assert(ip2long("dead:beaf::1") =:= 295990749943530982778020572095127224321),
    ?assert(ip2long(295990749943530982778020572095127224321) =:= 295990749943530982778020572095127224321).

long2ip_test() ->
    ?assert(long2ip(3232238081) =:= {192, 168, 10, 1}).

ipv4_to_ipv6_test() ->
    ?assert(ipv4_to_ipv6("192.168.10.1") =:= "::FFFF:192.168.10.1"),
    ?assert(ipv4_to_ipv6({192,168,10,1}) =:= "::FFFF:192.168.10.1").

is_ipv4_mapped_test() ->
    ?assert(is_ipv4_mapped("::FFFF:192.168.10.1") =:= true),
    ?assert(is_ipv4_mapped("192.168.10.1") =:= false).

broadcast_test() ->
    ?assert(broadcast("192.168.1.0/24") =:= {192, 168, 1, 255}),
    ?assert(broadcast("192.168.1.0/22") =:= {192, 168, 3, 255}).

number_of_hosts_test() ->
    ?assert(number_of_hosts("192.168.1.0/24") =:= 254),
    ?assert(number_of_hosts("192.168.1.0/22") =:= 1022).

range_test() ->
    ?assert(range("192.168.1.0/24") =:= {{192,168,1,1}, {192,168,1,254}}),
    ?assert(range("192.168.1.0/31") =:= {{192,168,1,0}, {192,168,1,1}}),
    ?assert(range("192.168.1.1/32") =:= {{192,168,1,1}, {192,168,1,1}}),
    ?assert(range("192.168.1.0/22") =:= {{192,168,0,1}, {192,168,3,254}}).

range2list_test() ->
    R1 = [{192,168,1,1}, {192,168,1,2}, {192,168,1,3}, {192,168,1,4}, {192,168,1,5}],
    ?assert(range2list("192.168.1.1-192.168.1.5") =:= R1),
    ?assert(length(range2list("192.168.1.0/24")) =:= 254),
    ?assert(length(range2list("192.168.1.0/22")) =:= 1022).

in_range_test() ->
    ?assert(in_range("192.168.1.10", "192.168.1.0/24") =:= true),
    ?assert(in_range("192.168.1.10", "192.168.1.0/22") =:= true),
    ?assert(in_range("192.168.7.10", "192.168.1.0/22") =:= false),
    ?assert(in_range("192.168.1.10", "192.168.1.0/255.255.255.0") =:= true).

bin_ipv6_to_string_test() ->
    Bin = <<222,173,190,175,0,0,0,0,0,0,0,0,0,0,0,1>>,
    IPv6 = "DEAD:BEAF:0000:0000:0000:0000:0000:0001",
    ?assert(bin_ipv6_to_string(Bin) =:= IPv6),
    ?assert(ipv6_to_binary(IPv6) =:= Bin).
