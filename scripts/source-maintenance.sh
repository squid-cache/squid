#!/bin/sh
#
# This script contains the code run to perform automatic source maintenance
#

## Source Code Format Enforcement
#
# A checker to recursively reformat all source files: .h .c .cc .cci
# using a custom astyle formatter and to use MD5 to validate that
# the formatter has not altered the code syntax.
#
# If code alteration takes place the process is halted for manual intervention.
#

# On squid-cache.org we have to use the python scripted md5sum
HOST=`hostname`
if test "$HOST" = "squid-cache.org" ; then
	MD5="md5"
else
	MD5="md5sum"
fi

ROOT=`bzr root`

ASVER=`astyle --version 2>&1 | grep -o -E "[0-9.]+"`
if test "${ASVER}" != "1.23" ; then
	echo "Astyle version problem. You have ${ASVER} instead of 1.23.";
else
	echo "Found astyle ${ASVER}. Formatting..."
fi

srcformat ()
{
PWD=`pwd`
#echo "FORMAT: ${PWD}..."

for FILENAME in `ls -1`; do

    case ${FILENAME} in

    *.h|*.c|*.cc|*.cci)

	#
	# Code Style formatting maintenance
	#
        if test "${ASVER}" = "1.23"; then
		${ROOT}/scripts/formater.pl ${FILENAME}
		if test -e $FILENAME -a -e "$FILENAME.astylebak"; then
			md51=`cat  $FILENAME| tr -d "\n \t\r" | $MD5`;
			md52=`cat  $FILENAME.astylebak| tr -d "\n \t\r" | $MD5`;

			if test "$md51" != "$md52" ; then
				echo "ERROR: File $PWD/$FILENAME not formating well";
				mv $FILENAME $FILENAME.astylebad
				mv $FILENAME.astylebak $FILENAME
			else
				rm -f $FILENAME.astylebak
			fi
        	fi
	fi

	#
	# REQUIRE config.h/squid.h as first #include
	#
	case ${FILENAME} in
	*.c|*.cc)
		FI=`grep "#include" ${FILENAME} | head -1`;
		if test "${FI}" != "#include \"config.h\"" -a "${FI}" != "#include \"squid.h\"" ; then
			echo "ERROR: ${PWD}/${FILENAME} does not include config.h or squid.h first!"
		fi
		;;
	*.h|*.cci)
		FI=`grep "#include \"config.h\"" ${FILENAME}`;
		if test "x${FI}" != "x" ; then
			echo "ERROR: ${PWD}/${FILENAME} duplicate include of config.h"
		fi
		;;
	esac

	#
	# DEBUG Section list maintenance
	#
	grep " DEBUG: section" <${FILENAME} | sed -e 's/ \* DEBUG: //' >>${ROOT}/doc/debug-sections.tmp

	#
	# File permissions maintenance.
	#
	chmod 644 ${FILENAME}
	;;

    *.pl|*.sh)
	#
	# File permissions maintenance.
	#
	chmod 755 ${FILENAME}
	;;

    Makefile.am)

    	perl -i -p -e 's/@([A-Z0-9_]+)@/\$($1)/g' <${FILENAME} >${FILENAME}.styled
	mv ${FILENAME}.styled ${FILENAME}
	;;

    esac

    if test "$FILENAME" = "libltdl" ; then
        :
    elif test -d $FILENAME ; then
	cd $FILENAME
	srcformat ${ROOT} || exit 1
	cd ..
    fi

done
}

echo "" >${ROOT}/doc/debug-sections.tmp
srcformat || exit 1
sort -u <${ROOT}/doc/debug-sections.tmp | sort -n >${ROOT}/doc/debug-sections.txt
rm ${ROOT}/doc/debug-sections.tmp
