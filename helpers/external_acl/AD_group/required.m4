for hdr in w32api/dsrole.h dsrole.h; do
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[#include <$hdr>]], [[
      PDSROLE_PRIMARY_DOMAIN_INFO_BASIC pDSRoleInfo;
      DWORD ret = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE *) & pDSRoleInfo);
    ]])
  ],[BUILD_HELPER="AD_group"],[])
done
