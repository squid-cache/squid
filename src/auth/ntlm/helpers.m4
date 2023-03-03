## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##
AS_IF([test "x$enable_auth" != "xno"],[
  NTLM_AUTH_HELPERS=""
  SQUID_HELPER_FEATURE_CHECK([auth_ntlm],[$enable_auth],[auth/ntlm],[
    # NP: we only need this list because m4_include() does not accept variables
    SQUID_CHECK_HELPER([fake],[auth/ntlm])
    SQUID_CHECK_HELPER([SMB_LM],[auth/ntlm])
    SQUID_CHECK_HELPER([SSPI],[auth/ntlm])
  ])
  NTLM_AUTH_HELPERS=$squid_cv_BUILD_HELPERS
  AUTH_MODULES="$AUTH_MODULES ntlm"
  AC_DEFINE([HAVE_AUTH_MODULE_NTLM],1,[NTLM auth module is built])
])
AM_CONDITIONAL(ENABLE_AUTH_NTLM, test "x$enable_auth_ntlm" != "xno")
AC_SUBST(NTLM_AUTH_HELPERS)

## NTLM requires some special Little-Endian conversion hacks
AS_IF([test "x$enable_auth_ntlm" != "xno"],[
  AC_CHECK_HEADERS(machine/byte_swap.h sys/bswap.h endian.h sys/endian.h)
  AC_CHECK_FUNCS(
    bswap_16 bswap16 \
    bswap_32 bswap32 \
    htole16 __htole16 \
    htole32 __htole32 \
    le16toh __le16toh \
    le32toh __le32toh \
  )
])
