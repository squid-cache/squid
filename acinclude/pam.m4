dnl 
dnl AUTHOR: Francesco Chemolli <kinkie@squid-cache.org>
dnl
dnl SQUID Web Proxy Cache          http://www.squid-cache.org/
dnl ----------------------------------------------------------
dnl Squid is the result of efforts by numerous individuals from
dnl the Internet community; see the CONTRIBUTORS file for full
dnl details.   Many organizations have provided support for Squid's
dnl development; see the SPONSORS file for full details.  Squid is
dnl Copyrighted (C) 2001 by the Regents of the University of
dnl California; see the COPYRIGHT file for full details.  Squid
dnl incorporates software developed and/or copyrighted by other
dnl sources; see the CREDITS file for full details.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.




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
password_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {}
static struct pam_conv conv = { &password_conversation, 0 };
]])], [
   squid_cv_pam_conv_signature=linux
], [ 
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <security/pam_appl.h>
static int
password_conversation(int num_msg, struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {}
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


