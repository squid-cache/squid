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
#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
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
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
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
HUGE_OBJECT_FLAG=""
AC_DEFUN([AC_TEST_CHECKFORHUGEOBJECTS],[
 if test "$GCC" = "yes"; then
  AC_MSG_CHECKING([whether compiler accepts -fhuge-objects])
  AC_CACHE_VAL([ac_cv_test_checkforhugeobjects],[
    ac_cv_test_checkforhugeobjects=`echo "int main(int argc, char **argv) { int foo; }" > conftest.cc
${CXX} -Werror -fhuge-objects -o conftest.bin conftest.cc 2>/dev/null
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
  fi
 fi #gcc
]) # end of AC_DEFUN of AC_TEST_CHECKFORHUGEOBJECTS


dnl ===========================================================================
dnl              http://autoconf-archive.cryp.to/ax_with_prog.html
dnl ===========================================================================
dnl
dnl SYNOPSIS
dnl
dnl   AX_WITH_PROG([VARIABLE],[program],[VALUE-IF-NOT-FOUND],[PATH])
dnl
dnl DESCRIPTION
dnl
dnl   Locates an installed program binary, placing the result in the precious
dnl   variable VARIABLE. Accepts a present VARIABLE, then --with-program, and
dnl   failing that searches for program in the given path (which defaults to
dnl   the system path). If program is found, VARIABLE is set to the full path
dnl   of the binary; if it is not found VARIABLE is set to VALUE-IF-NOT-FOUND
dnl   if provided, unchanged otherwise.
dnl
dnl   A typical example could be the following one:
dnl
dnl         AX_WITH_PROG(PERL,perl)
dnl
dnl   NOTE: This macro is based upon the original AX_WITH_PYTHON macro from
dnl   Dustin J. Mitchell <dustin@cs.uchicago.edu>.
dnl
dnl LAST MODIFICATION
dnl
dnl   2008-05-05
dnl
dnl COPYLEFT
dnl
dnl   Copyright (c) 2008 Francesco Salvestrini <salvestrini@users.sourceforge.net>
dnl   Copyright (c) 2008 Dustin J. Mitchell <dustin@cs.uchicago.edu>
dnl
dnl   Copying and distribution of this file, with or without modification, are
dnl   permitted in any medium without royalty provided the copyright notice
dnl   and this notice are preserved.
dnl
AC_DEFUN([AX_WITH_PROG],[
    AC_PREREQ([2.61])

    pushdef([VARIABLE],$1)
    pushdef([EXECUTABLE],$2)
    pushdef([VALUE_IF_NOT_FOUND],$3)
    pushdef([PATH_PROG],$4)

    AC_ARG_VAR(VARIABLE,Absolute path to EXECUTABLE executable)

    AS_IF(test -z "$VARIABLE",[
    	AC_MSG_CHECKING(whether EXECUTABLE executable path has been provided)
        AC_ARG_WITH(EXECUTABLE,AS_HELP_STRING([--with-EXECUTABLE=[[[[PATH]]]]],absolute path to EXECUTABLE executable), [
	    AS_IF([test "$withval" != "yes"],[
	        VARIABLE="$withval"
		AC_MSG_RESULT($VARIABLE)
	    ],[
		VARIABLE=""
	        AC_MSG_RESULT([no])
	    ])
	],[
	    AC_MSG_RESULT([no])
	])

        AS_IF(test -z "$VARIABLE",[
	    AC_PATH_PROG([]VARIABLE[],[]EXECUTABLE[],[]VALUE_IF_NOT_FOUND[],[]PATH_PROG[])
        ])
    ])

    popdef([PATH_PROG])
    popdef([VALUE_IF_NOT_FOUND])
    popdef([EXECUTABLE])
    popdef([VARIABLE])
])
