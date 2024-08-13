## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_CHECK_HEADERS([dsrole.h],[
  # required API feature
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#     if HAVE_WINDOWS_H
#     include <windows.h>
#     endif
#     if HAVE_DSROLE_H
#     include <dsrole.h>
#     endif
  ]], [[
      PDSROLE_PRIMARY_DOMAIN_INFO_BASIC pDSRoleInfo;
      DWORD ret = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE *) & pDSRoleInfo);
    ]])
  ],[BUILD_HELPER="AD_group"],[:])
  # required headers
  AC_CHECK_HEADERS([ \
    objbase.h \
    initguid.h \
    adsiid.h \
    iads.h \
    adshlp.h \
    adserr.h \
    lm.h \
    sddl.h
  ],[:],[BUILD_HELPER=""],[
#   if HAVE_WINDOWS_H
#   include <windows.h>
#   endif
#   if HAVE_IADS_H
#   include <iads.h>
#   endif
  ])
],,[
#  if HAVE_WINDOWS_H
#  include <windows.h>
#  endif
])
