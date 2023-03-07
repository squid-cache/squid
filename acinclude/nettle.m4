## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check whether libnettle Base64 uses the nettle 3.4 API
dnl which matters on 64-bit systems
dnl Defines HAVE_NETTLE34_BASE64 based on the result
dnl
AC_DEFUN([SQUID_CHECK_NETTLE_BASE64],[
  AC_CHECK_HEADERS(nettle/base64.h)
  AC_MSG_CHECKING([for Nettle 3.4 API compatibility])
  AH_TEMPLATE(HAVE_NETTLE34_BASE64,[set to 1 if Nettle 3.4 API will link])
  SQUID_STATE_SAVE(squid_nettle_base64_state)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#   include <cstddef>
#   include <cstdint>
#   include <nettle/base64.h>
  ]],[[
    char inData[10]; inData[0] = '\0';
    size_t srcLen = 0;
    struct base64_decode_ctx ctx;
    base64_decode_init(&ctx);
    uint8_t outData[10];
    size_t dstLen = 0;
    if (!base64_decode_update(&ctx, &dstLen, outData, srcLen, inData) ||
            !base64_decode_final(&ctx)) {
        return 1;
    }
  ]])],[AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_NETTLE34_BASE64,1,[set to 1 if Nettle 3.4 API will link])
  ],[AC_MSG_RESULT(no)])
  SQUID_STATE_ROLLBACK(squid_nettle_base64_state)
])
