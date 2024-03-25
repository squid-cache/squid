## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AS_IF([test "x$LIBMIT_KRB5_LIBS" != "x" -o "x$LIBHEIMDAL_KRB5_LIBS" != "x" -o "x$LIBGSS_LIBS" != "x"],[
  AS_IF([test "x$LIBLDAP_LIBS" != "x" -a "x$LIBSASL_LIBS" != "x"],[
    BUILD_HELPER="kerberos_ldap_group"
  ])
])
