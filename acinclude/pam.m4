## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check whether PAM's struct pam_conv takes a const (linux-style) or
dnl non-const (solaris-style) parametrs to the conv function.
dnl
dnl sets the shell variable squid_cv_pam_conv_signature to either
dnl "linux", "solaris" or "unknown".
dnl defines the C preprocessor macro PAM_CONV_FUNC_CONST_PARM to either
dnl "static" (linux-style) or the empty string (solaris-style or default)

AC_DEFUN([CHECK_STRUCT_PAM_CONV], [
  AH_TEMPLATE([PAM_CONV_FUNC_CONST_PARM],
    [Defined to const or empty depending on the style used by the OS to refer to the PAM message dialog func])
  AC_CACHE_CHECK([for PAM conversation struct signature type],
                  squid_cv_pam_conv_signature, [
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <security/pam_appl.h>
static int
password_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) { return 0; }
static struct pam_conv conv = { &password_conversation, 0 };
]])], [
   squid_cv_pam_conv_signature=linux
], [ 
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <security/pam_appl.h>
static int
password_conversation(int num_msg, struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) { return 0; }
static struct pam_conv conv = { &password_conversation, 0 };
]])], [ 
  squid_cv_pam_conv_signature=solaris
 ], [ 
  squid_cv_pam_conv_signature=unknown
  ])
    ])
  ])
  case $squid_cv_pam_conv_signature in
    linux) AC_DEFINE([PAM_CONV_FUNC_CONST_PARM],[const]) ;;
    solaris) AC_DEFINE([PAM_CONV_FUNC_CONST_PARM],[]) ;;
    *) AC_DEFINE([PAM_CONV_FUNC_CONST_PARM],[]) ;;
  esac
]) dnl CHECK_STRUCT_PAM_CONV


