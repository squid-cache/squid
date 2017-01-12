## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_external_acl_helpers list containing double entries.

#define list of modules to build
auto_ext_acl_modules=no
if test "x${enable_external_acl_helpers:=yes}" = "xyes" ;then
  SQUID_LOOK_FOR_MODULES([$srcdir/src/acl/external],[enable_external_acl_helpers])
  auto_ext_acl_modules=yes
fi
if test "x$enable_external_acl_helpers" = "xnone" ; then
  enable_external_acl_helpers=""
fi
EXTERNAL_ACL_HELPERS=""
enable_external_acl_helpers="`echo $enable_external_acl_helpers| sed -e 's/,/ /g;s/  */ /g'`"
if test "x$enable_external_acl_helpers" != "xno" ; then
  for helper in $enable_external_acl_helpers ; do
    dir="$srcdir/src/acl/external/$helper"

      # modules converted to autoconf macros already
      # NP: we only need this list because m4_include() does not accept variables
      if test "x$helper" = "xAD_group" ; then
        m4_include([src/acl/external/AD_group/required.m4])

      elif test "x$helper" = "xLDAP_group" ; then
        m4_include([src/acl/external/LDAP_group/required.m4])

      elif test "x$helper" = "xLM_group" ; then
        m4_include([src/acl/external/LM_group/required.m4])

      elif test "x$helper" = "xdelayer" ; then
        m4_include([src/acl/external/delayer/required.m4])

      elif test "x$helper" = "xSQL_session" ; then
        m4_include([src/acl/external/SQL_session/required.m4])

      elif test "x$helper" = "xeDirectory_userip" ; then
        m4_include([src/acl/external/eDirectory_userip/required.m4])

      elif test "x$helper" = "xfile_userip" ; then
        m4_include([src/acl/external/file_userip/required.m4])

      elif test "x$helper" = "xkerberos_ldap_group" ; then
        m4_include([src/acl/external/kerberos_ldap_group/required.m4])

      elif test "x$helper" = "xsession" ; then
        m4_include([src/acl/external/session/required.m4])

      elif test "x$helper" = "xtime_quota" ; then
        m4_include([src/acl/external/time_quota/required.m4])

      elif test "x$helper" = "xunix_group" ; then
        m4_include([src/acl/external/unix_group/required.m4])

      elif test "x$helper" = "xwbinfo_group" ; then
        m4_include([src/acl/external/wbinfo_group/required.m4])

      # modules not yet converted to autoconf macros (or third party drop-in's)
      elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
        BUILD_HELPER="$helper"
      fi

      if test -d "$srcdir/src/acl/external/$helper"; then
        if test "$BUILD_HELPER" != "$helper"; then
          if test "x$auto_ext_acl_modules" = "xyes"; then
            AC_MSG_NOTICE([external acl helper $helper ... found but cannot be built])
          else
            AC_MSG_ERROR([external acl helper $helper ... found but cannot be built])
          fi
        else
          EXTERNAL_ACL_HELPERS="$EXTERNAL_ACL_HELPERS $BUILD_HELPER"
        fi
      else
        AC_MSG_ERROR([external acl helper $helper ... not found])
      fi
  done
fi
AC_MSG_NOTICE([External acl helpers to be built: $EXTERNAL_ACL_HELPERS])
AC_SUBST(EXTERNAL_ACL_HELPERS)
