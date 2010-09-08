AC_DEFUN(AM_WITH_ERLANG,
[ AC_ARG_WITH(erlang,
          [AC_HELP_STRING([--with-erlang=PREFIX], [path to erlc and erl])])

   AC_PATH_TOOL(ERLC, erlc, , $with_erlang:$with_erlang/bin:$PATH)
   AC_PATH_TOOL(ERL, erl, , $with_erlang:$with_erlang/bin:$PATH)

   if test "z$ERLC" = "z" || test "z$ERL" = "z"; then
        AC_MSG_ERROR([erlang not found])
   fi

   cat >>conftest.erl <<_EOF
-module(conftest).
-author('alexey@sevcom.net').

-export([[start/0]]).

start() ->
    EIDirS = code:lib_dir("erl_interface") ++ "\n",
    EILibS =  libpath("erl_interface") ++ "\n",
    RootDirS = code:root_dir() ++ "\n",
    file:write_file("conftest.out", list_to_binary(EIDirS ++ EILibS ++ ssldef() ++ RootDirS)),
    halt().

ssldef() ->
   OTP = (catch erlang:system_info(otp_release)),
   if
    OTP >= "R14" -> "-DSSL40\n";
    OTP >= "R12" -> "-DSSL39\n";
        true -> ""
   end.

%% return physical architecture based on OS/Processor
archname() ->
    ArchStr = erlang:system_info(system_architecture),
    case os:type() of
    {win32, _} -> "windows";
    {unix,UnixName} ->
        Specs = string:tokens(ArchStr,"-"),
        Cpu = case lists:nth(2,Specs) of
              "pc" -> "x86";
              _ -> hd(Specs)
          end,
        atom_to_list(UnixName) ++ "-" ++ Cpu;
    _ -> "generic"
    end.

%% Return arch-based library path or a default value if this directory
%% does not exist
libpath(App) ->
    PrivDir    = code:priv_dir(App),
    ArchDir    = archname(),
    LibArchDir = filename:join([[PrivDir,"lib",ArchDir]]),
    case file:list_dir(LibArchDir) of
    %% Arch lib dir exists: We use it
    {ok, _List}  -> LibArchDir;
    %% Arch lib dir does not exist: Return the default value
    %% ({error, enoent}):
    _Error -> code:lib_dir("erl_interface") ++ "/lib"
    end.

_EOF

   if ! $ERLC conftest.erl; then
       AC_MSG_ERROR([could not compile sample program])
   fi

   if ! $ERL -s conftest -noshell; then
       AC_MSG_ERROR([could not run sample program])
   fi

   if ! test -f conftest.out; then
       AC_MSG_ERROR([erlang program was not properly executed, (conftest.out was not produced)])
   fi

   # First line
   ERLANG_EI_DIR=`cat conftest.out | head -n 1`
   # Second line
   ERLANG_EI_LIB=`cat conftest.out | head -n 2 | tail -n 1`
   # Third line
   ERLANG_SSL39=`cat conftest.out | head -n 3 | tail -n 1`
   # End line
   ERLANG_DIR=`cat conftest.out | tail -n 1`

   ERLANG_CFLAGS="-I$ERLANG_EI_DIR/include -I$ERLANG_DIR/usr/include"
   ERLANG_LIBS="-L$ERLANG_EI_LIB -lerl_interface -lei"

   AC_SUBST(ERLANG_CFLAGS)
   AC_SUBST(ERLANG_LIBS)
   AC_SUBST(ERLANG_SSL39)


   AC_SUBST(ERLC)
   AC_SUBST(ERL)
])

dnl <openssl>
AC_DEFUN(AM_WITH_OPENSSL,
[ AC_ARG_WITH(openssl,
      [AC_HELP_STRING([--with-openssl=PREFIX], [prefix where OPENSSL is installed])])
unset SSL_LIBS;
unset SSL_CFLAGS;
have_openssl=no
if test x"$tls" != x; then
    for ssl_prefix in $withval /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr; do
        printf "looking for openssl in $ssl_prefix...\n"
        SSL_CFLAGS="-I$ssl_prefix/include"
        SSL_LIBS="-L$ssl_prefix/lib -lcrypto"
        AC_CHECK_LIB(ssl, SSL_new, [ have_openssl=yes ], [ have_openssl=no ], [ $SSL_LIBS $SSL_CFLAGS ])
        if test x"$have_openssl" = xyes; then
            save_CPPFLAGS=$CPPFLAGS
            CPPFLAGS="-I$ssl_prefix/include $CPPFLAGS"
            AC_CHECK_HEADERS(openssl/ssl.h, have_openssl_h=yes)
            CPPFLAGS=$save_CPPFLAGS
            if test x"$have_openssl_h" = xyes; then
                have_openssl=yes
                printf "openssl found in $ssl_prefix\n";
                SSL_LIBS="-L$ssl_prefix/lib -lssl -lcrypto"
                CPPFLAGS="-I$ssl_prefix/include $CPPFLAGS"
                SSL_CFLAGS="-DHAVE_SSL"
                break
            fi
    else
        # Clear this from the autoconf cache, so in the next pass of
        # this loop with different -L arguments, it will test again.
        unset ac_cv_lib_ssl_SSL_new
        fi
    done
if test x${have_openssl} != xyes; then
    AC_MSG_ERROR([Could not find development files of OpenSSL library. Install them or disable `tls' with: --disable-tls])
fi
AC_SUBST(SSL_LIBS)
AC_SUBST(SSL_CFLAGS)
fi
])
dnl <openssl/>

