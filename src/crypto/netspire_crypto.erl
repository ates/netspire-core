-module(netspire_crypto).

-export([start/0, stop/0, info/0, info_lib/0]).
-export([md4/1, md4_init/0, md4_update/2, md4_final/1, des_ecb_encrypt/2, des_ecb_decrypt/2]).

-define(INFO, 0).
-define(MD4, 1).
-define(MD4_INIT, 2).
-define(MD4_UPDATE, 3).
-define(MD4_FINAL, 4).
-define(DES_ECB_ENCRYPT, 5).
-define(DES_ECB_DECRYPT, 6).
-define(INFO_LIB, 7).

-define(FUNC_LIST, [md4,
                    md4_init,
                    md4_update,
                    md4_final,
                    des_ecb_encrypt,
                    des_ecb_decrypt,
                    info_lib]).

start() ->
    application:start(netspire_crypto).

stop() ->
    application:stop(netspire_crypto).

info() ->
    lists:map(fun(I) -> lists:nth(I, ?FUNC_LIST) end,
              binary_to_list(control(?INFO, []))).

info_lib() ->
    <<_DrvVer:8, NameSize:8, Name:NameSize/binary,
      VerNum:32, VerStr/binary>> = control(?INFO_LIB, []),
    [{Name, VerNum, VerStr}].

md4(Data) ->
    control(?MD4, Data).

md4_init() ->
    control(?MD4_INIT, []).

md4_update(Context, Data) ->
    control(?MD4_UPDATE, [Context, Data]).

md4_final(Context) ->
    control(?MD4_FINAL, Context).

des_ecb_encrypt(Key, Data) ->
    control(?DES_ECB_ENCRYPT, [Key, Data]).

des_ecb_decrypt(Key, Data) ->
    control(?DES_ECB_DECRYPT, [Key, Data]).

control(Cmd, Data) ->
    Port = netspire_crypto_srv:client_port(),
    erlang:port_control(Port, Cmd, Data).

