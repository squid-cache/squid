## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

for hdr in w32api/dsrole.h dsrole.h; do
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[#include <$hdr>]], [[
      PDSROLE_PRIMARY_DOMAIN_INFO_BASIC pDSRoleInfo;
      DWORD ret = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE *) & pDSRoleInfo);
    ]])
  ],[BUILD_HELPER="AD_group"],[])
done
