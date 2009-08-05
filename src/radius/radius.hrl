%%%----------------------------------------------------------------------
%%% File : radius.hrl
%%% Purpose : Describes packet format of the RADIUS protocol (RFC 2865)
%%%----------------------------------------------------------------------

%%---------------------------------------------------------------------
%% Data Type: radius_packet
%% where:
%%    code: Identifies the type of RADIUS packet.
%%    ident: Aids in matching requests and replies.
%%    len: Indicates the length of the packet.
%%    auth: Used to authenticate the reply from the RADIUS server,
%%       and is used in the password hiding algorithm. 
%%    attrs: List of attributes that are required for the
%%%      type of service, as well as any desired optional attributes.
%%----------------------------------------------------------------------
-record(radius_packet, {code, ident, auth, attrs = []}).

%%---------------------------------------------------------------------
%% Data Type: nas_spec
%% where:
%%    ip: IP of the NAS.
%%    name: Identifies NAS.
%%    secret: Shared secret required for NAS authorization.
%%    module: Module suitable to handle requests from NAS.
%%----------------------------------------------------------------------
-record(nas_spec, {ip, name, secret, module}).

%%---------------------------------------------------------------------
%% Data Type: session
%%----------------------------------------------------------------------
-record(session, {id, ip, username, status, started_at, expires_at, finished_at, nas_spec, data}).

%%---------------------------------------------------------------------
%% Data Type: attribute
%% where:
%%    code: Numeric code of the attribute.
%%    type: Attribute type (octets/ipaddr/string/integer/date).
%%    name: Attribute name.
%%----------------------------------------------------------------------
-record(attribute, {code, type, name, opts}).
-define(VENDOR_SPECIFIC, 26).

%%---------------------------------------------------------------------
%% Data Type: value
%% where:
%%    aname: Attribute name
%%    vname: Attribute value name.
%%    value: Attribute value.
%%----------------------------------------------------------------------
-record(value, {aname, vname, value}).

-define(PACKET_LENGTH, 4096).

% The minimum length is 20 and maximum length is 4096.
-define(RADIUS_PACKET, Code:8, Ident:1/binary, Length:16, Auth:16/binary, Attrs/binary).

-define(ATTRIBUTE, Type:8, Length:8, Rest/binary).
-define(VENDOR_ATTRIBUTE, Id:4/integer-unit:8, Type, Length, Rest/binary).
