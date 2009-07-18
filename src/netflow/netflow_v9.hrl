-define(NF_V9_TEMPLATES_TABLE, netflow_v9_templates).

%% NetFlow header Version 9
-define(NF_V9_HEADER_FORMAT,
        Version:16,
        Count:16,
        SysUptime:32,
        UnixSecs:32,
        SequenceNum:32,
        SourceID:32
       ).

-record(nfh_v9, {
          version,
          count,
          sys_uptime,
          unix_secs,
          flow_seq,
          source_id}).
