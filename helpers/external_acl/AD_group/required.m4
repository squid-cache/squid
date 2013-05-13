#
## TODO: make a AC_COMPILE check instead
#
for hdr in w32api/dsrole.h dsrole.h; do
  AC_EGREP_HEADER(/usr/include/$hdr,[DsRoleGetPrimaryDomainInformation],[BUILD_HELPER="AD_group"])
done
