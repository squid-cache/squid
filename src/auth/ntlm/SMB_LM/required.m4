## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# DONT build this helper on Windows
# DONT build this helper by default
#
# XXX: do we really need the mingw check?
if test "$squid_host_os" != "mingw" -a "x$auto_auth_ntlm_modules" != "xyes"; then
  BUILD_HELPER="SMB_LM"
  AC_CHECK_HEADERS([w32api/windows.h windows.h],[BUILD_HELPER=""])
  AS_IF([test "x$BUILD_HELPER" = "xSMB_LM"],[require_smblib="yes"])
fi
