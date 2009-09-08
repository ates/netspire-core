AC_DEFUN(AM_WITH_ERLANG,
[ AC_ARG_WITH(erlang,
          [AC_HELP_STRING([--with-erlang=PREFIX], [path to erlc and erl])])

   AC_PATH_TOOL(ERLC, erlc, , $with_erlang:$with_erlang/bin:$PATH)
   AC_PATH_TOOL(ERL, erl, , $with_erlang:$with_erlang/bin:$PATH)

   if test "z$ERLC" = "z" || test "z$ERL" = "z"; then
        AC_MSG_ERROR([erlang not found])
   fi
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

