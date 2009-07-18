%%%----------------------------------------------------------------------
%%% File : netflow_v5.erl
%%% Purpose : NetFlow v5 protocol routines.
%%%----------------------------------------------------------------------
-module(netflow_v5).
-export([decode/1]).

-include("netflow_v5.hrl").

%%
%% API
%%

decode(Bin) ->
    try
        decode_packet(Bin)
    catch
        _:Reason ->
            {error, {badpdu, Reason}}
    end.

%%
%% Internal functions
%%

decode_packet(<<?NF_V5_HEADER_FORMAT, Rest/binary>>) ->
    Header = #nfh_v5 {version = Version,
                      count = Count,
                      sys_uptime = SysUptime,
                      unix_secs = UnixSecs,
                      unix_nsecs = UnixNsecs,
                      flow_seq = FlowSequence,
                      engine_type = EngineType,
                      engine_id = EngineID,
                      sampling_interval = SamplingInterval},
    {ok, {Header, decode_records(Rest, [])}}.

decode_records(<<>>, Acc0) ->
    lists:reverse(Acc0);
decode_records(<<?NF_V5_RECORD_FORMAT, Rest/binary>>, Acc0) ->
    Record = #nfrec_v5 {src_addr = SrcAddr,
                        dst_addr = DstAddr,
                        next_hop = NextHop,
                        input = Input,
                        output = Output,
                        d_pkts = Pkts,
                        d_octets = Octets,
                        first = First,
                        last = Last,
                        src_port = SrcPort,
                        dst_port = DstPort,
                        tcp_flags = TcpFlags,
                        prot = Prot,
                        tos = Tos,
                        src_as = SrcAs,
                        dst_as = DstAs,
                        src_mask = SrcMask,
                        dst_mask = DstMask},
    decode_records(Rest, [Record | Acc0]).
