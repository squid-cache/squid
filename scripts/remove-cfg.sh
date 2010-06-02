#!/bin/sh

# Removes an configuration file if it is identical to the default file,
# preventing "make distcheck" failures due to configuration leftovers.
# Intended to be used for installed configuration files.

remover=$1 # the program to remove a file
prime=$2   # the configuration file to be removed, including path
default=$3 # the default configuration filename, including path

# by default, use .default default extension
if test -z "$default"
then
	default="$prime.default"
fi

# is the primary configuration file present?
if test -f $prime
then
	# is the primary config identical to the default?
	if diff $default $prime > /dev/null
	then
 		echo " $remover -f $prime";
                $remover -f $prime;
        fi
fi

exit 0
