## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# DONT build this helper on Windows
#
# XXX: do we really need the mingw check?
if test "$squid_host_os" != "mingw"; then
  BUILD_HELPER="smb_lm"
  AC_CHECK_HEADERS([w32api/windows.h windows.h],[BUILD_HELPER=""])
fi
