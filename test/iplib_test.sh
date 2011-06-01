#!/usr/bin/env escript
%%! -pa ../ebin

-include_lib("eunit/include/eunit.hrl").

main([]) ->
    % ip2long
    ?assert(iplib:ip2long("192.168.10.1") =:= 3232238081),
    ?assert(iplib:ip2long({192, 168, 10, 1}) =:= 3232238081),
    ?assert(iplib:ip2long(3232238081) =:= 3232238081),
    ?assert(iplib:ip2long("dead:beaf::") =:= 295990749943530982778020572095127224320),
    ?assert(iplib:ip2long("dead:beaf::1") =:= 295990749943530982778020572095127224321),
    ?assert(iplib:ip2long(295990749943530982778020572095127224321) =:= 295990749943530982778020572095127224321),

    % long2ip
    ?assert(iplib:long2ip(3232238081) =:= {192, 168, 10, 1}),

    % ipv4_to_ipv6
    ?assert(iplib:ipv4_to_ipv6("192.168.10.1") =:= "::FFFF:192.168.10.1"),
    ?assert(iplib:ipv4_to_ipv6({192,168,10,1}) =:= "::FFFF:192.168.10.1"),

    % is_ipv4_mapped
    ?assert(iplib:is_ipv4_mapped("::FFFF:192.168.10.1") =:= true),
    ?assert(iplib:is_ipv4_mapped("192.168.10.1") =:= false),

    % broadcast
    ?assert(iplib:broadcast("192.168.1.0/24") =:= {192, 168, 1, 255}),
    ?assert(iplib:broadcast("192.168.1.0/22") =:= {192, 168, 3, 255}),

    % number_of_hosts
    ?assert(iplib:number_of_hosts("192.168.1.0/24") =:= 254),
    ?assert(iplib:number_of_hosts("192.168.1.0/22") =:= 1022),

    % range
    ?assert(iplib:range("192.168.1.0/24") =:= {{192,168,1,1}, {192,168,1,254}}),
    ?assert(iplib:range("192.168.1.0/31") =:= {{192,168,1,0}, {192,168,1,1}}),
    ?assert(iplib:range("192.168.1.1/32") =:= {{192,168,1,1}, {192,168,1,1}}),
    ?assert(iplib:range("192.168.1.0/22") =:= {{192,168,0,1}, {192,168,3,254}}),

    % range2list
    R1 = [{192,168,1,1}, {192,168,1,2}, {192,168,1,3}, {192,168,1,4}, {192,168,1,5}],
    ?assert(iplib:range2list("192.168.1.1-192.168.1.5") =:= R1),
    ?assert(length(iplib:range2list("192.168.1.0/24")) =:= 254),
    ?assert(length(iplib:range2list("192.168.1.0/22")) =:= 1022),

    % in_range
    ?assert(iplib:in_range("192.168.1.10", "192.168.1.0/24") =:= true),
    ?assert(iplib:in_range("192.168.1.10", "192.168.1.0/22") =:= true),
    ?assert(iplib:in_range("192.168.7.10", "192.168.1.0/22") =:= false),
    ?assert(iplib:in_range("192.168.1.10", "192.168.1.0/255.255.255.0") =:= true),

    % bin_ipv6_to_string & ipv6_to_binary
    Bin = <<222,173,190,175,0,0,0,0,0,0,0,0,0,0,0,1>>,
    IPv6 = "DEAD:BEAF:0000:0000:0000:0000:0000:0001",
    ?assert(iplib:bin_ipv6_to_string(Bin) =:= IPv6),
    ?assert(iplib:ipv6_to_binary(IPv6) =:= Bin),

    % is_macaddr
    ?assert(iplib:is_macaddr("AB:CD:EF:00:11:22") =:= true),
    ?assert(iplib:is_macaddr("AB-CD-EF-00-11-22") =:= true),
    ?assert(iplib:is_macaddr("ab:cd:ef:00:11:22") =:= true),
    ?assert(iplib:is_macaddr("ab-cd-ef-00-11-22") =:= true),
    ?assert(iplib:is_macaddr("ab-cz-ef-00-110-22") =:= false).
