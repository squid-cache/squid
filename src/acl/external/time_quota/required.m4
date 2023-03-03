## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

SQUID_CHECK_LIBTDB
if test "$with_tdb" != "no"; then
    BUILD_HELPER="time_quota"
fi
