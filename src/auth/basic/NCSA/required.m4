## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

BUILD_HELPER="NCSA"

# check for optional crypt(3), may require -lcrypt
SQUID_STATE_SAVE(ncsa_helper)
LIBS="$LIBS $CRYPTLIB"
AC_CHECK_FUNCS(crypt)
SQUID_STATE_ROLLBACK(ncsa_helper)
