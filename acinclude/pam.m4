## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check whether PAM's struct pam_conv takes a const (linux-style) or
dnl non-const (solaris-style) parametrs to the conv function.
dnl
dnl defines the C preprocessor macro PAM_CONV_FUNC_CONST_PARM to either
dnl "const" (linux-style) or the empty string (solaris-style or default)
AC_DEFUN([CHECK_STRUCT_PAM_CONV], [
  AH_TEMPLATE([PAM_CONV_FUNC_CONST_PARM],
    [Defined to const or empty depending on the style used by the OS to refer to the PAM message dialog func])
  AC_CACHE_CHECK([for PAM conversation struct signature type],
                  squid_cv_pam_conv_signature, [
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
static int
password_conversation(int, const struct pam_message **, struct pam_response **, void *) { return 0; }
static struct pam_conv conv = { &password_conversation, 0 };
]])], [
   squid_cv_pam_conv_signature=linux
],[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
static int
password_conversation(int, struct pam_message **, struct pam_response **, void *) { return 0; }
static struct pam_conv conv = { &password_conversation, 0 };
]])], [
  squid_cv_pam_conv_signature=solaris
 ],[
  squid_cv_pam_conv_signature=unknown
  ])
    ])
  ])
  AS_IF([test "$squid_cv_pam_conv_signature" = "linux"],
    AC_DEFINE([PAM_CONV_FUNC_CONST_PARM],[const]),
    AC_DEFINE([PAM_CONV_FUNC_CONST_PARM],[])
  )
]) dnl CHECK_STRUCT_PAM_CONV

dnl check for --with-pam option
AC_DEFUN_ONCE([SQUID_CHECK_LIBPAM],[
SQUID_AUTO_LIB(pam,[Pluggable Authentication Modules],[LIBPAM])
SQUID_CHECK_LIB_WORKS(pam,[
  LIBS="$LIBS $LIBPAM_PATH"
  PKG_CHECK_MODULES([LIBPAM],[pam],[:],[:])
  CPPFLAGS="$CPPFLAGS $LIBPAM_CFLAGS"
  AC_CHECK_HEADERS([security/pam_appl.h],[CHECK_STRUCT_PAM_CONV],[LIBPAM_LIBS=""])
])
]) dnl SQUID_CHECK_LIBPAM
