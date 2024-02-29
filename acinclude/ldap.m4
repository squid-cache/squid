# Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl checks for LDAP functionality
AC_DEFUN([SQUID_LDAP_TEST],[
  AC_CACHE_CHECK([for $1],[squid_cv_$1],[
    SQUID_STATE_SAVE(squid_ldap_test_state)
    LIBS="$LIBLDAP_PATH $LIBLDAP_LIBS $LIBPTHREADS"
    CPPFLAGS="-DLDAP_DEPRECATED=1 -DLDAP_REFERRALS $CPPFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#       if HAVE_LDAP_H
#       include <ldap.h>
#       elif HAVE_MOZLDAP_LDAP_H
#       include <mozldap/ldap.h>
#       endif
      ]],[[$2]])
    ],[
      squid_cv_$1=1
    ],[
      squid_cv_$1=0
    ],[
      squid_cv_$1=0
    ])
    SQUID_STATE_ROLLBACK(squid_ldap_test_state)
  ])
  AC_DEFINE_UNQUOTED([HAVE_$1],${squid_cv_$1},[Define to 1 if you have $1])
])

dnl similar to SQUID_LDAP_TEST but runs the test program
AC_DEFUN([SQUID_LDAP_TEST_RUN],[
  AC_CACHE_CHECK([for $1],[m4_translit([squid_cv_$1],[-+. ],[____])],[
    SQUID_STATE_SAVE(squid_ldap_test_state)
    LIBS="$LIBLDAP_PATH $LIBLDAP_LIBS $LIBPTHREADS"
    CPPFLAGS="-DLDAP_DEPRECATED=1 -DLDAP_REFERRALS $CPPFLAGS"
    AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#       if HAVE_LDAP_H
#       include <ldap.h>
#       elif HAVE_MOZLDAP_LDAP_H
#       include <mozldap/ldap.h>
#       endif
#       include <string.h>
      ]],[[$2]])
    ],[
      m4_translit([squid_cv_$1],[-+. ],[____])=1
    ],[
      m4_translit([squid_cv_$1],[-+. ],[____])=0
    ],[
      m4_translit([squid_cv_$1],[-+. ],[____])=0
    ])
    SQUID_STATE_ROLLBACK(squid_ldap_test_state)
  ])
  AC_DEFINE_UNQUOTED([m4_translit([m4_translit([HAVE_$1],[-+. abcdefghijklmnopqrstuvwxyz],[____ABCDEFGHIJKLMNOPQRSTUVWXYZ])],[-+. ],[____])],
    ${m4_translit([squid_cv_$1],[-+. ],[____])},[Define to 1 if you have $1])
])

dnl find the LDAP library vendor and define relevant HAVE_(vendor name) macro
AC_DEFUN([SQUID_LDAP_CHECK_VENDOR],[
  SQUID_LDAP_TEST_RUN([OpenLDAP],[return strcmp(LDAP_VENDOR_NAME,"OpenLDAP")])
  SQUID_LDAP_TEST_RUN([Sun LDAP SDK],[return strcmp(LDAP_VENDOR_NAME,"Sun Microsystems Inc.")])
  SQUID_LDAP_TEST_RUN([Mozilla LDAP SDK],[return strcmp(LDAP_VENDOR_NAME,"mozilla.org")])
])

dnl check whether the LDAP library(s) provide the needed API and types
dnl define HAVE_DAP_* macros for each checked item
AC_DEFUN([SQUID_CHECK_LDAP_API],[
  SQUID_LDAP_TEST([LDAP],[
    char host[]="";
    int port;
    ldap_init((const char *)&host, port);
  ])
  SQUID_LDAP_CHECK_VENDOR
  SQUID_LDAP_TEST([LDAP_OPT_DEBUG_LEVEL],[auto i=LDAP_OPT_DEBUG_LEVEL])
  SQUID_LDAP_TEST([LDAP_SCOPE_DEFAULT],[auto i=LDAP_SCOPE_DEFAULT])
  SQUID_LDAP_TEST([LDAP_REBIND_PROC],[LDAP_REBIND_PROC ldap_rebind])
  SQUID_LDAP_TEST([LDAP_REBINDPROC_CALLBACK],[LDAP_REBINDPROC_CALLBACK ldap_rebind])
  SQUID_LDAP_TEST([LDAP_REBIND_FUNCTION],[LDAP_REBIND_FUNCTION ldap_rebind])

  dnl TODO check this test's code actually works, it looks broken
  SQUID_LDAP_TEST([LDAP_URL_LUD_SCHEME],[struct ldap_url_desc.lud_scheme])

  AC_CHECK_LIB(ldap,[ldapssl_client_init],[
    AC_DEFINE(HAVE_LDAPSSL_CLIENT_INIT,1,[Define to 1 if you have ldapssl_client_init])
  ])
  dnl Extract library names for AC_SEARCH_LIBS() to iterate.
  LIBLDAP_NAMES="`echo "$LIBLDAP_LIBS" | sed -e 's/-l//g'`"
  dnl If a AC_SEARCH_LIBS() finds a required library X then subsequent calls
  dnl may produce a misleading "none required" result for the same library X
  dnl because the first successful search adds -lX to LIBS.
  AC_SEARCH_LIBS([ldap_url_desc2str],[$LIBLDAP_NAMES],[
    AC_DEFINE(HAVE_LDAP_URL_DESC2STR,1,[Define to 1 if you have ldap_url_desc2str])
  ])
  AC_SEARCH_LIBS([ldap_url_parse],[$LIBLDAP_NAMES],[
    AC_DEFINE(HAVE_LDAP_URL_PARSE,1,[Define to 1 if you have ldap_url_parse])
  ])
  AC_SEARCH_LIBS([ldap_start_tls_s],[$LIBLDAP_NAMES],[
    AC_DEFINE(HAVE_LDAP_START_TLS_S,1,[Define to 1 if you have ldap_start_tls_s])
  ])
  SQUID_STATE_ROLLBACK(squid_ldap_state)
])
