AC_PREREQ(0.1)
AC_INIT(src/netspire.erl,, ates@ipv6.dp.ua)

AC_PROG_CC
AC_PROG_MAKE_SET

if test "x$GCC" = "xyes"; then
    CFLAGS="$CFLAGS -Wall"
fi

AM_WITH_ERLANG

AC_C_CONST

# Change default prefix
AC_PREFIX_DEFAULT(/opt/netspire)

# Checks for library functions.
AC_FUNC_MALLOC
AC_HEADER_STDC

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 c_src/Makefile
                 src/crypto/Makefile
                 src/modules/Makefile
                 src/netflow/Makefile
                 src/radius/Makefile])

AM_WITH_OPENSSL

# If ssl is kerberized it need krb5.h
# On RedHat and OpenBSD, krb5.h is in an unsual place:
KRB5_INCLUDE="`krb5-config --cflags 2>/dev/null`"
if test -n "$KRB5_INCLUDE" ; then
    CPPFLAGS="$CPPFLAGS $KRB5_INCLUDE"
else
#         For RedHat                                  For BSD
    for D in /usr/kerberos/include /usr/include/kerberos /usr/include/kerberosV
        do
            if test -d $D ; then
                CPPFLAGS="$CPPFLAGS -I$D"
            fi
        done
fi
AC_CHECK_HEADER(krb5.h,,)

AC_OUTPUT
