dnl This encapsulates the nasty mess of headers we need to check when 
dnl checking types.
AC_DEFUN([SQUID_DEFAULT_INCLUDES],[[
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
AC_DEFUN([SQUID_DEFAULT_SIZEOF_INCLUDES],[
#include <stdio.h>
SQUID_DEFAULT_INCLUDES
])

dnl *BSD net headers
AC_DEFUN([SQUID_BSDNET_INCLUDES],[
SQUID_DEFAULT_INCLUDES
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#if HAVE_NETINET_IP_FIL_H
#include <netinet/ip_fil.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

dnl
dnl thanks to autogen, for the template..
dnl
dnl @synopsis  AC_TEST_CHECKFORHUGEOBJECTS
dnl
dnl Test whether -fhuge-objects is available with this c++ compiler. gcc-29.5 series compilers need this on some platform with large objects.
dnl
AC_DEFUN([AC_TEST_CHECKFORHUGEOBJECTS],[
  AC_MSG_CHECKING([whether compiler accepts -fhuge-objects])
  AC_CACHE_VAL([ac_cv_test_checkforhugeobjects],[
    ac_cv_test_checkforhugeobjects=`echo "int foo;" > conftest.cc
${CXX} -Werror -fhuge-objects -c conftest.cc 2>/dev/null
res=$?
rm -f conftest.*
echo yes
exit $res`
    if [[ $? -ne 0 ]]
    then ac_cv_test_checkforhugeobjects=no
    else if [[ -z "$ac_cv_test_checkforhugeobjects" ]]
         then ac_cv_test_checkforhugeobjects=yes
    fi ; fi
  ]) # end of CACHE_VAL
  AC_MSG_RESULT([${ac_cv_test_checkforhugeobjects}])

  if test "X${ac_cv_test_checkforhugeobjects}" != Xno
  then
    HUGE_OBJECT_FLAG="-fhuge-objects"
  else
    HUGE_OBJECT_FLAG=""
  fi
]) # end of AC_DEFUN of AC_TEST_CHECKFORHUGEOBJECTS
