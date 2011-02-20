-define(EAP_PACKET, Code:8, Ident:8, Length:16, Type:8, Data/binary).

-define(EAP_MD5_PACKET, Size:8, Data/binary).

-record(eap_client, {username, data, state}).

