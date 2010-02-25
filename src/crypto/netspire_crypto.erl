-module(netspire_crypto).

-export([info/0, info_lib/0, des_ecb_encrypt/2, des_ecb_decrypt/2]).

-define(INFO, 0).
-define(DES_ECB_ENCRYPT, 1).
-define(DES_ECB_DECRYPT, 2).
-define(INFO_LIB, 3).

-define(FUNC_LIST, [des_ecb_encrypt, des_ecb_decrypt, info_lib]).

info() ->
    lists:map(fun(I) -> lists:nth(I, ?FUNC_LIST) end,
              binary_to_list(control(?INFO, []))).

info_lib() ->
    <<_DrvVer:8, NameSize:8, Name:NameSize/binary,
      VerNum:32, VerStr/binary>> = control(?INFO_LIB, []),
    [{Name, VerNum, VerStr}].

des_ecb_encrypt(Key, Data) ->
    control(?DES_ECB_ENCRYPT, [Key, Data]).

des_ecb_decrypt(Key, Data) ->
    control(?DES_ECB_DECRYPT, [Key, Data]).

control(Cmd, Data) ->
    Port = netspire_crypto_srv:client_port(),
    erlang:port_control(Port, Cmd, Data).
