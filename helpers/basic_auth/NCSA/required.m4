BUILD_HELPER="NCSA"

# check for optional crypt(3), may require -lcrypt
SQUID_STATE_SAVE(ncsa_helper)
LIBS="$LIBS $CRYPTLIB"
AC_CHECK_FUNCS(crypt)
SQUID_STATE_ROLLBACK(ncsa_helper)
