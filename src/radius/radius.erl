%%%----------------------------------------------------------------------
%%% File : radius.erl
%%% Purpose : RADIUS (RFC-2865) protocol routines.
%%%----------------------------------------------------------------------
-module(radius).

-include("radius.hrl").

-export([decode_packet/1,
         encode_response/3,
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

attribute_value(Type, Packet) ->
    case lists:keysearch(Type, 1, Packet#radius_packet.attrs) of
        {value, {_Type, Value}} ->
            Value;
        false ->
            undefined
    end.

encode_response(Request, Response, Secret) ->
    #radius_packet{code = C, attrs = A} = Response,
    Code = <<C:8>>,
    Ident = Request#radius_packet.ident,
    ReqAuth = Request#radius_packet.auth,
    Attrs = encode_attributes(A, <<>>),
    Length = <<(20 + byte_size(Attrs)):16>>,
    Auth = erlang:md5([Code, Ident, Length, ReqAuth, Attrs, Secret]),
    [Code, Ident, Length, Auth, Attrs].

encode_attributes(undefined, <<>>) ->
    <<>>;
encode_attributes([], Bin) ->
    Bin;
encode_attributes([A | Attrs], Bin) ->
    encode_attributes(Attrs, concat_binary([Bin, encode_attribute(A)])).

encode_attribute({{Id, Type}, Value}) ->
    case radius_dict:lookup_attribute({Id, Type}) of
        not_found ->
            <<>>;
        A ->
            Bin = typecast_value(Value, A#attribute.type),
            Size = byte_size(Bin),
            VLength = 8 + Size,
            ALength = 2 + Size,
            <<?VENDOR_SPECIFIC:8, VLength:8, Id:32, Type:8, ALength:8, Bin/binary>>
    end;
encode_attribute({Type, Value}) ->
    case radius_dict:lookup_attribute(Type) of
        not_found ->
            <<>>;
        A ->
            Bin = typecast_value(Value, A#attribute.type),
            Length = 2 + byte_size(Bin),
            <<Type:8, Length:8, Bin/binary>>
    end.

typecast_value(Value, _Type) when is_binary(Value) ->
    Value;
typecast_value(Value, string) ->
    list_to_binary(Value);
typecast_value(Value, integer) ->
    <<Value:32>>;
typecast_value(Value, octets) when is_list(Value) ->
    list_to_binary(Value);
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
