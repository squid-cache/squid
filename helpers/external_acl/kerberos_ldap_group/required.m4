if test "x$with_krb5" == "xyes"; then
  BUILD_HELPER="kerberos_ldap_group"
  SQUID_CHECK_SASL
fi
