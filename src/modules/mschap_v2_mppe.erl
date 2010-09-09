%%% The implementation of Microsoft Point-to-Point Encryption (MPPE)
%%% RFC 2548, RFC 3079
-module(mschap_v2_mppe).

%% API
-export([generate_mppe_attrs/4]).

generate_mppe_attrs(NTResponse, PasswordHash, Auth, Secret) ->
    SendSalt = create_salt(),
    RecvSalt = create_salt(),
    MasterKey = get_master_key(PasswordHash, NTResponse),
    SHASendKey = get_asymmetric_start_key(MasterKey, magic3()),
    SHARecvKey = get_asymmetric_start_key(MasterKey, magic2()),
    PlainSendText = create_plain_text(SHASendKey),
    PlainRecvText = create_plain_text(SHARecvKey),

    SendKey = encrypt_keys(PlainSendText, Secret, Auth, SendSalt),
    RecvKey = encrypt_keys(PlainRecvText, Secret, Auth, RecvSalt),

    Keys = [{"MS-MPPE-Send-Key", SendKey}, {"MS-MPPE-Recv-Key", RecvKey}],
    Policy = case gen_module:get_option(mod_mschap_v2, require_encryption) of
        yes ->
            % Encryption required
            [{"MS-MPPE-Encryption-Policy", <<2:32>>}];
        _ ->
            % Encryption allowed
            [{"MS-MPPE-Encryption-Policy", <<1:32>>}]
    end,
    Types = case gen_module:get_option(mod_mschap_v2, require_strong) of
        yes ->
            % 128 bit keys 
            [{"MS-MPPE-Encryption-Types", <<4:32>>}];
        _ ->
            % 40- or 128-bit keys may be used
            [{"MS-MPPE-Encryption-Types", <<6:32>>}]
    end,
    Keys ++ Policy ++ Types.

%%
%% Internal functions
%%
create_salt() ->
    Salt1 = 128 + crypto:rand_uniform(0, 128),
    Salt2 = crypto:rand_uniform(0, 256),
    <<Salt1, Salt2>>.

%% Construct a plaintext version of the String field by concate-
%% nating the Key-Length and Key sub-fields.  If necessary, pad
%% the resulting string until its length (in octets) is an even
%% multiple of 16.  It is recommended that zero octets (0x00) be
%% used for padding.
create_plain_text(Key) ->
    <<16:8, Key:16/binary-unit:8, 0:120>>.

%% Call PlainText P. Call the shared secret S, the pseudo-random 128-bit Request
%% Authenticator (from the corresponding Access-Request packet) R,
%% and the contents of the Salt field A.  Break P into 16 octet
%% chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
%% ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
%% termediate values b(1), b(2)...c(i) are required.  Encryption
%% is performed in the following manner
%%      b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
%%      b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
%%                  .                      .
%%                  .                      .
%%      b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)
%%
%%      The   resulting   encrypted   String   field    will    contain
%%      c(1)+c(2)+...+c(i).
encrypt_keys(PlainText, Secret, Authenticator, Salt) ->
    B = crypto:md5([Secret, Authenticator, Salt]),
    <<P1:16/binary-unit:8, P2:16/binary-unit:8>> = PlainText,
    C = netspire_util:do_bxor(P1, B),
    B1 = crypto:md5([Secret, C]),
    C1 = netspire_util:do_bxor(P2, B1),
    list_to_binary([Salt, C, C1]).

get_master_key(PasswordHash, NTResponse) ->
    PasswordHashHash = crypto:md4(PasswordHash),
    ShaContext = crypto:sha_init(),
    ShaContext1 = crypto:sha_update(ShaContext, PasswordHashHash),
    ShaContext2 = crypto:sha_update(ShaContext1, NTResponse),
    ShaContext3 = crypto:sha_update(ShaContext2, magic1()),
    Digest = crypto:sha_final(ShaContext3),
    <<MasterKey:16/binary-unit:8, _/binary>> = Digest,
    MasterKey.

get_asymmetric_start_key(MasterKey, Magic) ->
    ShaContext = crypto:sha_init(),
    ShaContext1 = crypto:sha_update(ShaContext, MasterKey),
    ShaContext2 = crypto:sha_update(ShaContext1, sha_pad1()),
    ShaContext3 = crypto:sha_update(ShaContext2, Magic),
    ShaContext4 = crypto:sha_update(ShaContext3, sha_pad2()),
    Digest = crypto:sha_final(ShaContext4),
    <<Key:16/binary-unit:8, _/binary>> = Digest,
    Key.

magic1() ->
   <<16#54, 16#68, 16#69, 16#73, 16#20, 16#69, 16#73, 16#20, 16#74,
     16#68, 16#65, 16#20, 16#4d, 16#50, 16#50, 16#45, 16#20, 16#4d,
     16#61, 16#73, 16#74, 16#65, 16#72, 16#20, 16#4b, 16#65, 16#79>>.

magic2() ->
    <<16#4F, 16#6E, 16#20, 16#74, 16#68, 16#65, 16#20, 16#63, 16#6C, 16#69,
      16#65, 16#6E, 16#74, 16#20, 16#73, 16#69, 16#64, 16#65, 16#2C, 16#20,
      16#74, 16#68, 16#69, 16#73, 16#20, 16#69, 16#73, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#73, 16#65, 16#6E, 16#64, 16#20, 16#6B, 16#65, 16#79,
      16#3B, 16#20, 16#6F, 16#6E, 16#20, 16#74, 16#68, 16#65, 16#20, 16#73,
      16#65, 16#72, 16#76, 16#65, 16#72, 16#20, 16#73, 16#69, 16#64, 16#65,
      16#2C, 16#20, 16#69, 16#74, 16#20, 16#69, 16#73, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#72, 16#65, 16#63, 16#65, 16#69, 16#76, 16#65, 16#20,
      16#6B, 16#65, 16#79, 16#2E>>.

magic3() ->
    <<16#4F, 16#6E, 16#20, 16#74, 16#68, 16#65, 16#20, 16#63, 16#6C, 16#69,
      16#65, 16#6E, 16#74, 16#20, 16#73, 16#69, 16#64, 16#65, 16#2C, 16#20,
      16#74, 16#68, 16#69, 16#73, 16#20, 16#69, 16#73, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#72, 16#65, 16#63, 16#65, 16#69, 16#76, 16#65, 16#20,
      16#6B, 16#65, 16#79, 16#3B, 16#20, 16#6F, 16#6E, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#73, 16#65, 16#72, 16#76, 16#65, 16#72, 16#20, 16#73,
      16#69, 16#64, 16#65, 16#2C, 16#20, 16#69, 16#74, 16#20, 16#69, 16#73,
      16#20, 16#74, 16#68, 16#65, 16#20, 16#73, 16#65, 16#6E, 16#64, 16#20,
      16#6B, 16#65, 16#79, 16#2E>>.

sha_pad1() ->
    <<16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00>>.

sha_pad2() ->
    <<16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2,
      16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2,
      16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2,
      16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2>>.

