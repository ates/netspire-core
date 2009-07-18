%%%----------------------------------------------------------------------
%%% File : netflow_v9.erl
%%% Purpose : NetFlow v9 (RFC-3954) protocol routines.
%%%----------------------------------------------------------------------
-module(netflow_v9).
-export([init/0, decode/2]).
-include("netflow_v9.hrl").

init() ->
    case ets:info(?NF_V9_TEMPLATES_TABLE) of
        undefined ->
            ets:new(?NF_V9_TEMPLATES_TABLE, [named_table, public]);
        _ ->
            ok
    end.

decode(Bin, IP) ->
    try
        decode_packet(Bin, IP)
    catch
        _:Reason ->
            {error, Reason}
    end.

decode_packet(<<?NF_V9_HEADER_FORMAT, Rest/binary>>, IP) ->
    Header = #nfh_v9 {version = Version,
                      count = Count,
                      sys_uptime = SysUptime,
                      unix_secs = UnixSecs,
                      flow_seq = SequenceNum,
                      source_id = SourceID},
    case decode_flowsets(Rest, {SourceID, IP}, []) of
        {ok, Records} ->
            {ok, {Header, Records}};
        {error, Reason} ->
            {error, Reason}
    end.

decode_flowsets(<<>>, _, Acc0) ->
    {ok, lists:reverse(Acc0)};
%% Template flowset
decode_flowsets(<<0:16, Length:16, Rest/binary>>, Domain, Acc0) ->
    decode_templates(Rest, Domain, Length - 4, Acc0);
%% Options template flowset
decode_flowsets(<<1:16, Length:16, Rest/binary>>, Domain, Acc0) ->
    decode_options_templates(Rest, Domain, Length - 4, Acc0);
%% Data flowset
decode_flowsets(<<ID:16, Length:16, Rest/binary>>, Domain, Acc0) when ID > 255 ->
    case lookup_template(Domain, ID) of
        false ->
            {error, missing_template};
        {_Size, Map} = Template ->
            decode_data_fields(Rest, Domain, Length - 4, Template, Map, Acc0, [])
    end.

decode_templates(Bin, Domain, 0, Acc0) ->
    decode_flowsets(Bin, Domain, Acc0);
decode_templates(<<ID:16, Count:16, Rest/binary>>, Domain, Length, Acc0) ->
    decode_template_fields(Rest, Domain, ID, Length - 4, Count, Acc0, []).

%% Decode template flowset fields
decode_template_fields(Bin, Domain, ID, 0, 0, Acc0, Acc1) ->
    store_template(Domain, ID, lists:reverse(Acc1)),
    decode_templates(Bin, Domain, 0, Acc0);
decode_template_fields(Bin, Domain, ID, Length, 0, Acc0, Acc1) ->
    store_template(Domain, ID, lists:reverse(Acc1)),
    decode_templates(Bin, Domain, Length, Acc0);
decode_template_fields(<<Type:16, Len:16, Rest/binary>>, Domain, ID, Length, Count, Acc0, Acc1) ->
    decode_template_fields(Rest, Domain, ID, Length - 4, Count - 1, Acc0, [{Type, Len} | Acc1]).

%% Decode data flowset fields
decode_data_fields(Bin, Domain, 0, _, _, Acc0, []) ->
    decode_flowsets(Bin, Domain, Acc0);
decode_data_fields(Bin, Domain, Length, {S, Map}, [], Acc0, Acc1) ->
    Record = lists:reverse(Acc1),
    decode_data_fields(Bin, Domain, Length - S, {S, Map}, Map, [Record | Acc0], []);
decode_data_fields(Bin, Domain, Length, {S, Map}, [{scope, {Type, Len}} | T], Acc0, Acc1) when Length >= S ->
    <<Value:Len/binary, Rest/binary>> = Bin,
    Scope = typecast_field(Value, {scope, {Type, Len}}),
    decode_data_fields(Rest, Domain, Length, {S, Map}, T, Acc0, [Scope | Acc1]);
decode_data_fields(Bin, Domain, Length, {S, Map}, [{Type, Len} | T], Acc0, Acc1) when Length >= S ->
    <<Value:Len/binary, Rest/binary>> = Bin,
    Field = typecast_field(Value, Type, Len),
    decode_data_fields(Rest, Domain, Length, {S, Map}, T, Acc0, [Field | Acc1]);
decode_data_fields(Bin, Domain, Length, _, _, Acc0, []) ->
    <<_:Length/binary-unit:8, Rest/binary>> = Bin,
    decode_flowsets(Rest, Domain, Acc0).

decode_options_templates(Bin, Domain, 0, Acc0) ->
    decode_flowsets(Bin, Domain, Acc0);
decode_options_templates(<<ID:16, ScopeLen:16, OptionLen:16, Rest/binary>>, Domain, Length, Acc0) ->
    decode_options_template_fields(Rest, Domain, ID, Length - 6, ScopeLen, OptionLen, Acc0, []).

decode_options_template_fields(Bin, Domain, ID, 0, 0, 0, Acc0, Acc1) ->
    store_template(Domain, ID, lists:reverse(Acc1)),
    decode_flowsets(Bin, Domain, Acc0);
decode_options_template_fields(Bin, Domain, ID, Length, 0, 0, Acc0, Acc1) ->
    store_template(Domain, ID, lists:reverse(Acc1)),
    <<_:Length/binary-unit:8, Rest/binary>> = Bin,
    decode_flowsets(Rest, Domain, Acc0);
decode_options_template_fields(<<Type:16, Len:16, Rest/binary>>, Domain, ID, Length, 0, OptionLen, Acc0, Acc1) ->
    decode_options_template_fields(Rest, Domain, ID, Length - 4, 0, OptionLen - 4, Acc0, [{Type, Len} | Acc1]);
decode_options_template_fields(<<Type:16, Len:16, Rest/binary>>, Domain, ID, Length, ScopeLen, OptionLen, Acc0, Acc1) ->
    decode_options_template_fields(Rest, Domain, ID, Length - 4, ScopeLen - 4, OptionLen, Acc0, [{scope, {Type, Len}} | Acc1]).

lookup_template(Domain, ID) ->
    case ets:lookup(?NF_V9_TEMPLATES_TABLE, {Domain, ID}) of
        [] ->
            false;
        [{_, Map}] ->
            Map
    end.

store_template(Domain, ID, Map) ->
    Size = lists:foldl(fun record_size/2, 0, Map),
    ets:insert(?NF_V9_TEMPLATES_TABLE, {{Domain, ID}, {Size, Map}}).

record_size({scope, {_, Size}}, Total) ->
    Size + Total;
record_size({_, Size}, Total) ->
    Size + Total.

typecast_field(_Bin, {scope, {1, 0}}) ->
    {scope, 'SYSTEM'};
typecast_field(_Bin, {scope, {Type, 0}}) ->
    {scope, Type};
typecast_field(Bin, {scope, {2, Length}}) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {scope, {'IFACE', Value}};
typecast_field(Bin, {scope, {3, Length}}) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {scope, {'LINE_CARD', Value}};
typecast_field(Bin, {scope, {4, Length}}) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {scope, {'CACHE', Value}};
typecast_field(Bin, {scope, {5, Length}}) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {scope, {'TEMPLATE', Value}};
typecast_field(Bin, {scope, {Type, _}}) ->
    {scope, {Type, Bin}}.
typecast_field(Bin, 1, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'IN_BYTES', Value};
typecast_field(Bin, 2, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'IN_PKTS', Value};
typecast_field(Bin, 3, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'FLOWS', Value};
typecast_field(Bin, 10, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'INPUT_SNMP', Value};
typecast_field(Bin, 14, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'OUTPUT_SNMP', Value};
typecast_field(Bin, 16, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'SRC_AS', Value};
typecast_field(Bin, 17, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'DST_AS', Value};
typecast_field(Bin, 23, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'OUT_BYTES', Value};
typecast_field(Bin, 24, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'OUT_PKTS', Value};
typecast_field(Bin, 27, 16) ->
    {'IPV6_SRC_ADDR', Bin};
typecast_field(Bin, 28, 16) ->
    {'IPV6_DST_ADDR', Bin};
typecast_field(Bin, 40, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'TOTAL_BYTES_EXP', Value};
typecast_field(Bin, 41, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'TOTAL_PKTS_EXP', Value};
typecast_field(Bin, 42, Length) ->
    <<Value:Length/integer-unit:8>> = Bin,
    {'TOTAL_FLOWS_EXP', Value};
typecast_field(<<Value>>, 4, 1) ->
    {'PROTOCOL', Value};
typecast_field(<<Value>>, 5, 1) ->
    {'SRC_TOS', Value};
typecast_field(<<Value>>, 6, 1) ->
    {'TCP_FLAGS', Value};
typecast_field(<<Value:16>>, 7, 2) ->
    {'L4_SRC_PORT', Value};
typecast_field(<<A, B, C, D>>, 8, 4) ->
    {'IPV4_SRC_ADDR', {A, B, C, D}};
typecast_field(<<Value>>, 9, 1) ->
    {'SRC_MASK', Value};
typecast_field(<<Value:16>>, 11, 2) ->
    {'L4_DST_PORT', Value};
typecast_field(<<A, B, C, D>>, 12, 4) ->
    {'IPV4_DST_ADDR', {A, B, C, D}};
typecast_field(<<Value>>, 13, 1) ->
    {'DST_MASK', Value};
typecast_field(<<A, B, C, D>>, 15, 4) ->
    {'IPV4_NEXT_HOP', {A, B, C, D}};
typecast_field(<<Value:32>>, 21, 4) ->
    {'LAST_SWITCHED', Value};
typecast_field(<<Value:32>>, 22, 4) ->
    {'FIRST_SWITCHED', Value};
typecast_field(<<Value>>, 29, 1) ->
    {'IPV6_SRC_MASK', Value};
typecast_field(<<Value>>, 30, 1) ->
    {'IPV6_DST_MASK', Value};
typecast_field(<<Value>>, 32, 2) ->
    {'ICMP_TYPE', Value};
typecast_field(<<Value>>, 48, 1) ->
    {'FLOW_SAMPLER_ID', Value};
typecast_field(<<Value>>, 49, 1) ->
    {'FLOW_SAMPLER_MODE', Value};
typecast_field(<<Value:32>>, 50, 4) ->
    {'FLOW_SAMPLER_RANDOM_INTERVAL', Value};
typecast_field(<<Value>>, 52, 1) ->
    {'MIN_TTL', Value};
typecast_field(<<Value>>, 53, 1) ->
    {'MAX_TTL', Value};
typecast_field(<<Value:16>>, 54, 2) ->
    {'IPV4_IDENT', Value};
typecast_field(Bin, 56, 6) ->
    {'IN_SRC_MAC', Bin};
typecast_field(Bin, 57, 6) ->
    {'OUT_DST_MAC', Bin};
typecast_field(<<Value>>, 60, 1) ->
    {'IP_PROTOCOL_VERSION', Value};
typecast_field(<<Value>>, 61, 1) ->
    {'DIRECTION', Value};
typecast_field(Bin, 62, 16) ->
    {'IPV6_NEXT_HOP', Bin};
typecast_field(Value, 63, 16) ->
    {'BPG_IPV6_NEXT_HOP', Value};
typecast_field(Bin, Type, _) ->
    {Type, Bin}.
