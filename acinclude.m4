dnl This encapsulates the nasty mess of headers we need to check when 
dnl checking types.
AC_DEFUN(SQUID_DEFAULT_INCLUDES,[[
/* What a mess.. many systems have added the (now standard) bit types
 * in their own ways, so we need to scan a wide variety of headers to
 * find them..
 * IMPORTANT: Keep include/squid_types.h syncronised with this list
 */
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif  
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#if HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
]])     

dnl and this is for AC_CHECK_SIZEOF
AC_DEFUN(SQUID_DEFAULT_SIZEOF_INCLUDES,[
#include <stdio.h>
SQUID_DEFAULT_INCLUDES
])

dnl *BSD net headers
AC_DEFUN(SQUID_BSDNET_INCLUDES,[
SQUID_DEFAULT_INCLUDES
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#if HAVE_NETINET_IP_FIL_H
#include <netinet/ip_fil.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
])
