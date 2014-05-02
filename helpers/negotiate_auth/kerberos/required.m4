# FIXME: use other kerberos library checks from main configure.ac
AC_CHECK_HEADERS([gssapi/gssapi.h gssapi.h kerberosV/gssapi.h],[BUILD_HELPER="kerberos"])
