## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl requires libpam, indicated by --with-pam
AS_IF([test "x$with_pam" = "xyes"],[BUILD_HELPER="PAM"])
