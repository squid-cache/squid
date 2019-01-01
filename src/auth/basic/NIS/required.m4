## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

BUILD_HELPER="NIS"
AC_CHECK_HEADERS([sys/types.h rpc/rpc.h rpcsvc/ypclnt.h rpcsvc/yp_prot.h crypt.h],[],[BUILD_HELPER=""],AC_INCLUDES_DEFAULT([
#if HAVE_RPC_RPC_H
#include <rpc/rpc.h>
#endif
]))
