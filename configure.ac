AC_INIT([Netspire], [0.1], [], [])

AC_PREREQ(0.1)

AC_PROG_CC
AC_PROG_MAKE_SET

AM_WITH_ERLANG
AM_WITH_OPENSSL

# Change default prefix
AC_PREFIX_DEFAULT(/usr/local/)

# Checks for library functions.
AC_C_CONST
AC_FUNC_MALLOC
AC_HEADER_STDC

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([c_src/Makefile])
AC_CONFIG_FILES([src/crypto/Makefile])
AC_CONFIG_FILES([src/modules/Makefile])
AC_CONFIG_FILES([src/netflow/Makefile])
AC_CONFIG_FILES([src/radius/Makefile])

AC_OUTPUT
