#!/bin/sh
echo "/* automatically generated `date` by
echo   * $0 $*"
echo " * do not edit"
echo " */"
echo "#include \"squid.h\""
echo ""
for module in "$@"; do
   echo "REMOVALPOLICYCREATE createRemovalPolicy_${module};"
done
echo "RemovalPolicy * createRemovalPolicy(RemovalPolicySettings *settings)"
echo "{"
for module in "$@"; do
   echo "	if (strcmp(settings->type, \"${module}\") == 0)"
   echo "		return createRemovalPolicy_${module}(settings->args);"
done
   echo "	debug(20,1)(\"Unknown policy %s\n\", settings->type);"
   echo "	return NULL;"
echo "}"
