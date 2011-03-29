-define(EAP_PACKET, Code:8, Ident:8, Length:16, Type:8, Data/binary).

-define(EAP_MD5_PACKET, Size:8, Data/binary).

-define(EAP_MSCHAPV2_PACKET, OpCode:8, MSv2Id:8, MSLen:16, ValueSize:8, Response:49/binary-unit:8, Name:4/binary-unit:8).

%% EAP Message codes
-define(EAP_REQUEST, 1).
-define(EAP_RESPONSE, 2).
-define(EAP_SUCCESS, 3).
-define(EAP_FAILURE, 4).

%% EAP Type codes
-define(EAP_IDENTIFY, 1).
-define(EAP_NOTIFICATION, 2).
-define(EAP_NAK, 3).
-define(EAP_MD5_CHALLENGE, 4).
-define(EAP_OTP, 5). % One-Time Password (OTP) (RFC 1938)
-define(EAP_GTC, 6). % Generic Token Card

%% EAP Authentication codes
-define(EAP_TLS, 13).
-define(EAP_LEAP, 17).
-define(EAP_TTLS, 21).
-define(EAP_PEAP, 25).
-define(EAP_MSCHAPV2, 26).

-define(EAP_MSCHAPV2_RESPONSE, 26).
