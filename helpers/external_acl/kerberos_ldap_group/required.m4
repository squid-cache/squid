## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

if test "x$with_krb5" == "xyes"; then
  BUILD_HELPER="kerberos_ldap_group"
  if test "x$with_apple_krb5" = "xyes" ; then
    AC_CHECK_LIB(resolv, [main], [XTRA_LIBS="$XTRA_LIBS -lresolv"],[
      AC_MSG_ERROR([library 'resolv' is required for Apple Kerberos])
    ])
  fi
  SQUID_CHECK_SASL
fi
