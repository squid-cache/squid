SQUID_CHECK_SASL

# on success, add to the built modules list
if test "x$squid_cv_check_sasl" = "xyes"; then
  BUILD_HELPER="SASL"
fi
