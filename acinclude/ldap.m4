# Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl checks for LDAP functionality
AC_DEFUN([SQUID_LDAP_TEST],[
  AC_CACHE_CHECK([for $1],[squid_cv_$1],[
    SQUID_STATE_SAVE(squid_ldap_test_state)
    LIBS="$LDAPLIB $LBERLIB $LIBPTHREADS"
    CXXFLAGS="-DLDAP_DEPRECATED=1 -DLDAP_REFERRALS $CXXFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#       if HAVE_LDAP_H
#       include <ldap.h>
#       elif HAVE_MOZLDAP_LDAP_H
#       include <mozldap/ldap.h>
#       endif
      ]],[[$2]])
      SQUID_STATE_ROLLBACK(squid_ldap_test_state)
    ],[
      squid_cv_$1=1
    ],[
      squid_cv_$1=0
    ],[
      squid_cv_$1=0
    ])
  ])
  AC_DEFINE([HAVE_$1],[${squid_cv_$1}],[Define to 1 if you have $1])
])

dnl similar to SQUID_LDAP_TEST but runs the test program
AC_DEFUN([SQUID_LDAP_TEST_RUN],[
  AC_CACHE_CHECK([for $1],[m4_translit([squid_cv_$1],[-+. ],[____])],[
    SQUID_STATE_SAVE(squid_ldap_test_state)
    LIBS="$LDAPLIB $LBERLIB $LIBPTHREADS"
    CXXFLAGS="-DLDAP_DEPRECATED=1 -DLDAP_REFERRALS $CXXFLAGS"
    AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#       if HAVE_LDAP_H
#       include <ldap.h>
#       elif HAVE_MOZLDAP_LDAP_H
#       include <mozldap/ldap.h>
#       endif
#       include <string.h>
      ]],[[$2]])
      SQUID_STATE_ROLLBACK(squid_ldap_test_state)
    ],[
      m4_translit([squid_cv_$1],[-+. ],[____])=1
    ],[
      m4_translit([squid_cv_$1],[-+. ],[____])=0
    ],[
      m4_translit([squid_cv_$1],[-+. ],[____])=0
    ])
  ])
  AC_DEFINE([m4_translit([m4_translit([HAVE_$1],[-+. abcdefghijklmnopqrstuvwxyz],[____ABCDEFGHIJKLMNOPQRSTUVWXYZ])],[-+. ],[____])],
    [${m4_translit([squid_cv_$1],[-+. ],[____])}],[Define to 1 if you have $1])
])

AC_DEFUN([SQUID_LDAP_CHECK_VENDOR],[
  SQUID_LDAP_TEST_RUN([OpenLDAP],[return strcmp(LDAP_VENDOR_NAME,"OpenLDAP")])
  SQUID_LDAP_TEST_RUN([Sun LDAP SDK],[return strcmp(LDAP_VENDOR_NAME,"Sun Microsystems Inc.")])
  SQUID_LDAP_TEST_RUN([Mozilla LDAP SDK],[return strcmp(LDAP_VENDOR_NAME,"mozilla.org")])
])

