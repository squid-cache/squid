#!/bin/sh

# NOTE: echo '\n' is not portable.  Some shells interpret and
# change it to an actual newline character.  The ugly hack here
# is to use two echo commands:
# 	echo -n 'blah\'
#	echo 'n'
# This is probably more portable in Perl.

echo "/* automatically generated `date` by"
echo " *   $0 $*"
echo ' * do not edit'
echo ' */'
echo '#include "squid.h"'
echo ''
for module in "$@"; do
   echo "REMOVALPOLICYCREATE createRemovalPolicy_${module};"
done
echo ''
echo 'RemovalPolicy *'
echo 'createRemovalPolicy(RemovalPolicySettings *settings)'
echo '{'
for module in "$@"; do
   echo "        if (strcmp(settings->type, \"${module}\") == 0)"
   echo "            return createRemovalPolicy_${module}(settings->args);"
done
   echo -n '        debug(20, 1) ("Unknown policy %s\'
   echo 'n", settings->type);'
   echo '        return NULL;'
echo '}'
