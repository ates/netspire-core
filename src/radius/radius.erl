%%%----------------------------------------------------------------------
%%% File : radius.erl
%%% Purpose : RADIUS (RFC-2865) protocol routines.
%%%----------------------------------------------------------------------
-module(radius).

-include("radius.hrl").

-export([decode_packet/1,
         encode_packet/3,
         encode_response/3,
         encode_attributes/1,
         identify_packet/1,
         attribute_value/2]).

decode_packet(Packet) ->
    try
        <<?RADIUS_PACKET>> = Packet,
        case byte_size(Attrs) >= (Length - 20) of
            true ->
                A = decode_attributes(Attrs, []),
                {ok, #radius_packet{code = Code, ident = Ident, auth = Auth, attrs = A}};
            false ->
                invalid
        end
    catch
        _:_ ->
            invalid
    end.

decode_attributes(<<>>, Attrs) ->
    lists:reverse(Attrs);
decode_attributes(Bin, Attrs) ->
    case decode_attribute(Bin) of
        {unknown, Rest} ->
            decode_attributes(Rest, Attrs);
        {ok, Type, Value, Rest} ->
            decode_attributes(Rest, [{Type, Value} | Attrs])
     end.

decode_attribute(<<?ATTRIBUTE>>) ->
    L = (Length - 2),
    case radius_dict:lookup_attribute(Type) of
        not_found ->
            {_Value, Rest1} = decode_value(Rest, L),
            {unknown, Rest1};
        A ->
            case Type of
                ?VENDOR_SPECIFIC ->
                    decode_vendor_attribute(Rest);
                _ ->
                    {Value, Rest1} = decode_value(Rest, L, A#attribute.type),
                    {ok, Type, Value, Rest1}
            end
    end.

decode_vendor_attribute(<<?VENDOR_ATTRIBUTE>>) ->
    L = (Length - 2),
    case radius_dict:lookup_attribute({Id, Type}) of
        not_found ->
            {_Value, Rest1} = decode_value(Rest, L),
            {unknown, Rest1};
        A ->
            {Value, Rest1} = decode_value(Rest, L, A#attribute.type),
            {ok, {Id, Type}, Value, Rest1}
    end.

decode_value(Bin, Length, string) ->
    <<Value:Length/binary, Rest/binary>> = Bin,
    {binary_to_list(Value), Rest};
decode_value(Bin, Length, integer) ->
    <<Value:Length/integer-unit:8, Rest/binary>> = Bin,
    {Value, Rest};
decode_value(Bin, Length, ipaddr) ->
    <<Value : Length/binary, Rest/binary>> = Bin,
    IP = binary_to_list(Value),
    {list_to_tuple(IP), Rest};
decode_value(Bin, Length, _Type) ->
    decode_value(Bin, Length).

decode_value(Bin, Length) ->
    <<Value : Length/binary, Rest/binary>> = Bin,
    {Value, Rest}.

attribute_value(Code, Packet) when is_record(Packet, radius_packet) ->
    attribute_value(Code, Packet#radius_packet.attrs);
attribute_value(Code, Attrs) when is_list(Attrs) ->
    case radius_dict:lookup_attribute(Code) of
        not_found ->
            undefined;
        #attribute{code = Code1, name = Name} ->
            lookup_value(Code1, Name, Attrs)
    end.

lookup_value(Code, Name, Attrs) ->
    case lists:keysearch(Code, 1, Attrs) of
        {value, {_, Value}} ->
            Value;
        false ->
            case lists:keysearch(Name, 1, Attrs) of
                {value, {_, Value}} ->
                    Value;
                false ->
                    undefined
            end
    end.

encode_packet(Code, Attrs, Secret) ->
    Ident = 0,
    Attrs1 = radius:encode_attributes(Attrs),
    Length = <<(20 + byte_size(Attrs1)):16>>,
    Auth = erlang:md5([Code, Ident, Length, <<0:128>>, Attrs1, Secret]),
    [Code, Ident, Length, Auth, Attrs].

encode_response(Request, Response, Secret) ->
    #radius_packet{code = C, attrs = A} = Response,
    Code = <<C:8>>,
    Ident = Request#radius_packet.ident,
    ReqAuth = Request#radius_packet.auth,
    Attrs = encode_attributes(A, <<>>),
    Length = <<(20 + byte_size(Attrs)):16>>,
    Auth = erlang:md5([Code, Ident, Length, ReqAuth, Attrs, Secret]),
    [Code, Ident, Length, Auth, Attrs].

encode_attributes(Attrs) ->
    encode_attributes(Attrs, <<>>).

encode_attributes(undefined, <<>>) ->
    <<>>;
encode_attributes([], Bin) ->
    Bin;
encode_attributes([A | Attrs], Bin) ->
    encode_attributes(Attrs, concat_binary([Bin, encode_attribute(A)])).

encode_attribute({Code, Value}) ->
    case radius_dict:lookup_attribute(Code) of
        not_found ->
            <<>>;
        #attribute{code = Code1, type = Type} ->
            encode_attribute(Code1, Type, Value)
    end.

encode_attribute({Id, Code}, Type, Value) ->
    Bin = typecast_value(Value, Type),
    Size = byte_size(Bin),
    VLength = 8 + Size,
    ALength = 2 + Size,
    <<?VENDOR_SPECIFIC:8, VLength:8, Id:32, Code:8, ALength:8, Bin/binary>>;
encode_attribute(Code, Type, Value) ->
    Bin = typecast_value(Value, Type),
    Length = 2 + byte_size(Bin),
    <<Code:8, Length:8, Bin/binary>>.

typecast_value(Value, _Type) when is_binary(Value) ->
    Value;
typecast_value(Value, string) ->
    list_to_binary(Value);
typecast_value(Value, integer) when is_list(Value) ->
    Value1 = list_to_integer(Value),
    <<Value1:32>>;
typecast_value(Value, integer) ->
    <<Value:32>>;
typecast_value(Value, octets) when is_list(Value) ->
    list_to_binary(Value);
typecast_value(IP, ipaddr) when is_list(IP) ->
    {ok, {A, B, C, D}} = inet_parse:address(IP),
    <<A:8, B:8, C:8, D:8>>;
typecast_value({A, B, C, D}, ipaddr) ->
    <<A:8, B:8, C:8, D:8>>.

identify_packet(1) ->
    {ok, 'Access-Request'};
identify_packet(4) ->
    {ok, 'Accounting-Request'};
identify_packet(40) ->
    {ok, 'Disconnect-Request'};
identify_packet(41) ->
    {ok, 'Disconnect-ACK'};
identify_packet(42) ->
    {ok, 'Disconnect-NAK'};
identify_packet(Type) ->
    {unknown, Type}.
